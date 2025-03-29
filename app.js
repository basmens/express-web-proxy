import express from 'express';
import cookieParser from 'cookie-parser';
import { Readable } from 'stream';

const app = express();
const port = 3000;
const fallBackDomain = 'https://www.example.com';

let recentRequests = [];
const rateLimitWindow = 3000; // Time window for the requests to count in ms
const rateLimitCount = 2; // Max amount of allowed requests for that time window, inclusive

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
 * Transfers http headers from a list and extracts the relevant ones,
 * and potentially modifies them, to return them as a new object.
 * @param {Object.<string, string> | Headers} source The source map of headers.
 * @param {string} proxyDomain The domain of the proxy.
 * @param {string} pretendDomain The source domain the headers should pretend by.
 * @returns {Object.<string, string>} The transferred headers.
 */
function transferHeaders(source, proxyDomain, pretendDomain) {
  let result = {};
  if (source instanceof Headers) {
    source.forEach((value, key) => (result[key] = value));
  } else {
    result = { ...source };
  }

  if (result.host) result.host = pretendDomain;
  if (result.origin) result.origin = pretendDomain;
  if (result['content-security-policy'])
    result['content-security-policy'] =
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
      `report-uri http://${proxyDomain}/debug/csp`;

  if (result['content-length']) delete result['content-length'];
  if (result['content-encoding']) delete result['content-encoding'];
  if (result['cookie']) delete result['cookie'];
  if (result['set-cookie']) delete result['set-cookie'];

  return result;
}

/**
 * Tries to inject the proxy target into the given html. It replaces http(s)://path?query
 * with http://proxyDomain/http(s).path?query.
 * @param {string} html The html string.
 * @param {string} rawProxyTarget The raw proxy target.
 * @returns {string} The resulting string.
 */
function injectProxyTarget(html, proxyDomain) {
  var urlRegex = new RegExp(
    [
      /(?<startChar>.?)/,
      /(?<protocol>(?:https?:|))/,
      /(?<delimiter>\/|\\u002f){2}/,
      /(?<domain>[^\s.\\/:]+\.[^\s\\/:]+|localhost)/,
      /(?<port>:[0-9]+|)/,
      /(?<path>[^"'`<\s?:]*)/,
      /(?<query>(?:\?[^"'`<\s:]*)?)/,
    ]
      .map((r) => r.source)
      .join(''),
  );

  return html.replace(urlRegex, (_full, startChar, protocol, delimiter, domain, port, path, query) => {
    const replacement = [
      `${startChar}${protocol}${delimiter.repeat(2)}${proxyDomain}`,
      `${port}`,
      `${delimiter}`,
      `${(protocol && protocol.replace(':', '.')) || 'http.'}${domain}`,
      `${path}`,
      `${query}`,
    ].join('');

    return replacement;
  });
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
 * exceeded, it sends a client request to the server on the given proxy target and url.
 * @param {Express.Request} req The client request to proxy.
 * @param {ReadableStream} bodyStream The body of the request in the form of a stream.
 * @param {string} proxyTarget The proxy target.
 * @param {string} url The url on which to send the request.
 * @returns {Promise<Response>} A promise that resolves in the response from the server.
 */
async function sendClientRequest(req, bodyStream, proxyTarget, url) {
  // Rate limit
  const path = url.split('?', 2)[0];
  if (checkRateLimit(req.ip, req['user-agent'], proxyTarget, path)) return new Response(null, { status: 429 });

  // Send request
  return fetch(proxyTarget + url, {
    method: req.method,
    headers: transferHeaders(req.headers, req.headers.host, proxyTarget.split('://')[1]),
    body: bodyStream,
    duplex: 'half',
  });
}

/**
 * Goes through the list of proxy targets in the cookies and tries them until a
 * successful response has been received. Any that came before that successful
 * response are removed from the cookies. If no successful response was received,
 * the first one is returned instead.
 * @param {Express.Request} req The request to proxy.
 * @returns {Promise<Response | undefined>} The successful server response or the first one.
 */
async function proxyClientRequestOnCookies(req) {
  let bodyStream = ['GET', 'HEAD', 'TRACE'].includes(req.method) ? undefined : Readable.toWeb(req);
  const attemptedProxyTargets = new Set();
  const proxyTargets = req.cookies.proxyTargets;

  // Go through possible proxy targets until a successful response is found
  let bestResponse, bestProxyTargetIndex;
  for (const [index, proxyTarget] of proxyTargets.entries()) {
    if (attemptedProxyTargets.has(proxyTarget)) continue;
    attemptedProxyTargets.add(proxyTarget);

    let bodyStreamTee;
    if (bodyStream) [bodyStream, bodyStreamTee] = bodyStream.tee();
    const response = await sendClientRequest(req, bodyStreamTee, proxyTarget, req.url);

    if (!bestResponse) [bestResponse, bestProxyTargetIndex] = [response, index];
    if (response.status < 400) {
      [bestResponse, bestProxyTargetIndex] = [response, index];
      break;
    }
  }

  // Remove any wrong proxy targets from the cookies if applicable
  if (bestProxyTargetIndex > 0 && bestResponse.ok) proxyTargets.splice(0, bestProxyTargetIndex);
  return bestResponse;
}

/**
 * Takes the client request and proxies it to the server. The server response
 * is then returned. If applicable, the proxy target cookies are modified in req.
 * @param {Express.Request} req The request to proxy.
 * @returns {Promise<Response | undefined>} The server response.
 */
async function proxyClientRequest(req) {
  let proxyTarget;
  let url;
  if (req.url.startsWith('/http')) {
    const proxyTargetUrlPair = getAbsoluteProxyTarget(req.url);
    [proxyTarget, url] = [proxyTargetUrlPair.proxyTarget, proxyTargetUrlPair.modifiedUrl];
  } else if (Array.isArray(req.cookies.proxyTargets) && req.cookies.proxyTargets.length > 0) {
    return proxyClientRequestOnCookies(req);
  } else {
    [proxyTarget, url] = [fallBackDomain, '/'];
  }

  const bodyStream = ['GET', 'HEAD', 'TRACE'].includes(req.method) ? undefined : Readable.toWeb(req);
  const response = await sendClientRequest(req, bodyStream, proxyTarget, url);

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
    let response = await proxyClientRequest(req);
    if (!response) throw new Error('Proxying client request did not deliver a response');

    const host = req.headers.host; // This includes the port
    res.status(response.status);
    res.set(transferHeaders(response.headers, host, host));
    res.cookie('proxyTargets', JSON.stringify(req.cookies.proxyTargets), {
      maxAge: 9000000000,
      httpOnly: false,
      secure: true,
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
      type.includes('javascript') ||
      type.includes('json') ||
      type.includes('text')
    ) {
      res.send(injectProxyTarget(await response.text(), host));
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
 * Start server
 */
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
