import express from 'express';
import cookieParser from 'cookie-parser';
import { Readable } from 'stream';
import cookie from 'cookie';

const app = express();
const port = 3000;
const fallBackDomain = 'https://www.example.com';

let recentRequests = [];
const rateLimitWindow = 3000; // Time window for the requests to count in ms
const rateLimitCount = 10; // Max amount of allowed requests for that time window, inclusive

/**
 * Takes in a url that starts with an absolute proxy target in the path. That proxy
 * target is extracted and cut out of the url. The proxy target and the modified url
 * are then returned.
 * @param {string} url The url to get the absolute proxy target from.
 * @returns {{proxyTarget: string, modifiedUrl: string}} The proxy target together with the modified url.
 */
function getAbsoluteProxyTarget(url) {
  const parts = url.substring(1).split('/');
  const proxyTarget = parts.shift().replace('.', '://');
  return { proxyTarget, modifiedUrl: '/' + parts.join('/') };
}

/**
 * Transforms the headers from browser requests so that they can be
 * used to send to the proxy target.
 *
 * @param {Express.Request} req The request from the browser.
 * @param {string} proxyTarget The proxy target
 * @returns {Headers} A Headers instance containing the transferred headers.
 */
function transformHeadersForRequest(req, proxyTarget) {
  let resultHeaders = new Headers();

  Object.entries(req.headers).forEach(([name, value]) => {
    switch (name) {
      case 'host':
      case 'origin':
        resultHeaders.set(name, proxyTarget);
        break;
      case 'content-length':
      case 'content-encoding':
        break;
      default:
        resultHeaders.set(name, value);
        break;
    }
  });

  Object.entries(req.cookies).forEach(([name, value]) => {
    if (name !== 'proxyTarget') {
      resultHeaders.append('Set-Cookie', `${name}=${value}`);
    }
  });

  return resultHeaders;
}

/**
 * Translates a cookie header to a format that can be used as a cookie for Express
 *
 * @param {string} cookieHeaderValue A cookie value from a 'set-cookie' header
 * @returns {{cookieName: string, cookieValue: string, cookieOptions: Object}} values that can be passed to Express.Response.cookie
 */
function translateCookieForExpress(cookieHeaderValue) {
  const cookieName = cookieHeaderValue.slice(0, cookieHeaderValue.indexOf('='));
  const parsedCookie = cookie.parse(cookieHeaderValue);

  // Extract the cookie value from the parsedCookie
  const cookieValue = parsedCookie[cookieName];
  delete parsedCookie[cookieName];

  // For Express 'expires' needs to be a Date instead of a string.
  if (parsedCookie.Expires) {
    parsedCookie.expires = new Date(parsedCookie.Expires);
    delete parsedCookie.Expires;
  } else if (parsedCookie.expires) {
    parsedCookie.expires = new Date(parsedCookie.expires);
  }

  return {
    cookieName: cookieName,
    cookieValue: cookieValue,
    cookieOptions: parsedCookie,
  };
}

/**
 * transform headers that are received from the proxy target to so that they
 * are usable to send to the browser.
 *
 * @param {Response} proxyResponse The response from the proxy target
 * @param {Express.Response} res The response to send to the browser
 * @param {string} proxyTarget The proxy target
 */
function transformHeadersForResponse(proxyResponse, res, proxyTarget) {
  for (const [name, value] of proxyResponse.headers) {
    switch (name) {
      case 'set-cookie':
        {
          const { cookieName, cookieValue, cookieOptions } = translateCookieForExpress(value);

          if (cookieOptions.Domain) {
            cookieOptions.domain = proxyTarget.split(':')[0];
            delete cookieOptions.Domain;
          } else if (cookieOptions.domain) {
            cookieOptions.domain = proxyTarget.split(':')[0];
          }

          res.cookie(cookieName, cookieValue, cookieOptions);
        }
        break;
      case 'content-security-policy':
        res.set(
          name,
          "default-src 'self' data: 'unsafe-inline' 'unsafe-eval' https:; " +
            "script-src 'self' data: 'unsafe-inline' 'unsafe-eval' https: blob:; " +
            "style-src 'self' data: 'unsafe-inline' https:; " +
            "img-src 'self' data: https: blob:; " +
            "font-src 'self' data: https:; " +
            "connect-src 'self' data: https: wss: blob:; " +
            "media-src 'self' data: https: blob:; " +
            "object-src 'self' https:; " +
            "child-src 'self' https: data: blob:; " +
            "form-action 'self' https:; " +
            `report-uri http://${proxyTarget}/debug/csp`,
        );
        break;
      case 'content-length':
      case 'content-encoding':
      case 'connection':
        break;
      default:
        res.set(name, value);
        break;
    }
  }

  res.set('Access-Control-Allow-Origin', '*');
}

/**
 * Tries to inject the proxy target into the given html. It replaces http(s)://path?query
 * with http://proxyDomain/http(s).path?query.
 * @param {string} html The html string.
 * @param {string} proxyDomain The raw proxy target.
 * @returns {string} The resulting string.
 */
function injectProxyTarget(html, proxyDomain) {
  var urlRegex = new RegExp(
    [
      /(?<startChars>\S*?)/,
      /(?<protocol>https?:|)/,
      /(?<delimiter>\/|\\u002f){2}/,
      /(?<domain>(?:[^\s"'`<.\\/:]+\.[^"'`<\s\\/:]+)|localhost)/,
      /(?<targetPort>:[0-9]+|)/,
      /(?<path>[^"'`<\s?:]*)/,
      /(?<query>(?:\?[^"'`<\s:]*)?)/,
    ]
      .map((r) => r.source)
      .join(''),
    'gi',
  );

  let result = html.replace(urlRegex, (full, startChars, protocol, delimiter, domain, targetPort, path, query) => {
    if (startChars.endsWith('\\')) return full;
    if (startChars.includes('xmlns')) return full;

    const replacement = [
      `${startChars}http:${delimiter.repeat(2)}${proxyDomain}`,
      `${delimiter}`,
      `${protocol ? protocol.replace(':', '.') : 'http.'}${domain}${targetPort}`,
      `${path}`,
      `${query}`,
    ].join('');

    return replacement;
  });

  return result;
}

/**
 * Checks if a req on a given proxy target has exceeded the rate limit.
 * @param {string} ip The ip on which the request came in.
 * @param {string} userAgent The user-agent of the request.
 * @param {string} proxyTarget The proxy target.
 * @param {string} path The path of the url of the request.
 * @returns {boolean} True if rate limit is exceeded, false otherwise.
 */
function checkRateLimit(ip, userAgent, proxyTarget, path) {
  const now = new Date().getTime();
  recentRequests.push({
    ip: ip,
    'user-agent': userAgent,
    proxyTarget: proxyTarget,
    path: path,
    time: now,
  });

  while (recentRequests.length > 0 && now - recentRequests[0].time > rateLimitWindow) recentRequests.shift();

  let count = 0;
  for (const r of recentRequests) {
    if (r.ip === ip && r['user-agent'] === userAgent && r.proxyTarget === proxyTarget && r.path === path) count++;
  }
  return count > rateLimitCount;
}

/**
 * First does a rate limit check. If the rate limit is exceeded, an empty response
 * with a 429 'too many requests' status code is returned. If the rate limit is not
 * exceeded, it sends the browser request to the given proxy target on the given url.
 * @param {Express.Request} req The browser request to proxy.
 * @param {ReadableStream} bodyStream The body of the request in the form of a stream.
 * @param {string} proxyTarget The proxy target.
 * @param {string} url The url on which to send the request.
 * @returns {Promise<Response>} A promise that resolves in the response from the proxy target.
 */
async function sendBrowserRequest(req, bodyStream, proxyTarget, url) {
  // Rate limit
  const path = url.split('?', 2)[0];
  if (checkRateLimit(req.ip, req['user-agent'], proxyTarget, path)) {
    return new Response(null, { status: 429 });
  }

  // Send request
  return fetch(proxyTarget + url, {
    method: req.method,
    headers: transformHeadersForRequest(req, proxyTarget.split('://')[1]),
    body: bodyStream,
    duplex: 'half',
  });
}

/**
 * Goes through the list of proxy targets in the cookies and tries them until a
 * successful response has been received. Any that came before that successful
 * response are removed from the cookies. If no successful response was received,
 * the first one is returned.
 * @param {Express.Request} req The request to proxy.
 * @returns {Promise<Response | undefined>} The successful proxy target response or the first one.
 */
async function proxyBrowserRequestOnCookies(req) {
  let bodyStream = ['GET', 'HEAD', 'TRACE'].includes(req.method) ? undefined : Readable.toWeb(req);
  const attemptedProxyTargets = new Set();

  // Go through possible proxy targets until a successful response is found
  let bestResponse, bestProxyTargetIndex;
  for (const [index, proxyTarget] of req.cookies.proxyTargets.entries()) {
    if (attemptedProxyTargets.has(proxyTarget)) continue;
    attemptedProxyTargets.add(proxyTarget);

    let bodyStreamTee;
    if (bodyStream) [bodyStream, bodyStreamTee] = bodyStream.tee();
    const response = await sendBrowserRequest(req, bodyStreamTee, proxyTarget, req.url);

    if (!bestResponse) [bestResponse, bestProxyTargetIndex] = [response, index];
    if (response.status < 400) {
      [bestResponse, bestProxyTargetIndex] = [response, index];
      break;
    }
  }

  // Remove any wrong proxy targets from the cookies if applicable
  if (bestProxyTargetIndex > 0 && bestResponse.ok) req.cookies.proxyTargets.splice(0, bestProxyTargetIndex);
  return bestResponse;
}

/**
 * Takes the browser request and proxies it to the proxy target. The proxy target response
 * is then returned. If applicable, the proxy target cookies are modified in req.
 * @param {Express.Request} req The request to proxy.
 * @returns {Promise<Response | undefined>} The proxy target response.
 */
async function proxyBrowserRequest(req) {
  let proxyTarget;
  let url;
  if (req.url.startsWith('/http')) {
    const proxyTargetUrlPair = getAbsoluteProxyTarget(req.url);
    [proxyTarget, url] = [proxyTargetUrlPair.proxyTarget, proxyTargetUrlPair.modifiedUrl];
  } else if (Array.isArray(req.cookies.proxyTargets) && req.cookies.proxyTargets.length > 0) {
    return proxyBrowserRequestOnCookies(req);
  } else {
    [proxyTarget, url] = [fallBackDomain, '/'];
  }

  const bodyStream = ['GET', 'HEAD', 'TRACE'].includes(req.method) ? undefined : Readable.toWeb(req);
  const response = await sendBrowserRequest(req, bodyStream, proxyTarget, url);

  // Potentially add new proxyTarget to cookies
  if (
    response.ok &&
    req.method === 'GET' &&
    response.headers.get('content-type').includes('html') &&
    (req.cookies.proxyTargets.length === 0 || req.cookies.proxyTargets[0] !== proxyTarget)
  )
    req.cookies.proxyTargets.unshift(proxyTarget);

  return response;
}

/*
 * Parse cookies and proxy targets
 */
app.use(cookieParser());
app.use((req, _res, next) => {
  req.cookies.proxyTargets = JSON.parse(req.cookies.proxyTargets || '[]');
  next();
});

/*
 * Content security endpoint for debugging
 */
app.post('/debug/csp', express.json({ type: '*/csp-report' }));
app.post('/debug/csp', (req, res) => {
  console.log(`CSP violation while proxying ${req.cookies.proxyTarget}: ${JSON.stringify(req.body, undefined, 2)}`);
  res.status(200).send();
});

/*
 * Proxy requests
 */
app.all('/**', async (req, res, next) => {
  try {
    let response = await proxyBrowserRequest(req);
    if (!response) throw new Error('Proxying client request did not deliver a response');

    const host = req.headers.host; // This includes the port
    res.status(response.status);
    res.set(transformHeadersForResponse(response, res, host));
    res.cookie('proxyTargets', JSON.stringify(req.cookies.proxyTargets), {
      maxAge: 9000000000,
      httpOnly: false,
      secure: false,
    });

    // Handle requests without a type simply
    const type = response.headers.get('content-type');
    if (!type) {
      res.send();
      return;
    }

    // Send body
    if (
      type.includes('html') ||
      type.includes('css') ||
      type.includes('scss') ||
      type.includes('javascript') ||
      type.includes('json') ||
      type.includes('text') ||
      type.includes('svg')
    ) {
      res.send(injectProxyTarget(await response.text(), req.headers.host));
    } else {
      res.setHeader('content-length', response.headers.get('content-length'));
      Readable.fromWeb(response.body).pipe(res);
    }
  } catch (err) {
    next(err);
  }
});

/*
 * Catching errors
 */
app.use((err, req, res, _next) => {
  console.log(err);
  res.status(500).send(err);
});

/*
 * Start proxy
 */
app.listen(port, () => {
  console.log(`Proxy listening on port ${port}`);
});
