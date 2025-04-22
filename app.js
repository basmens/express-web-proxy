import express from 'express';
import cookieParser from 'cookie-parser';
import { Readable } from 'stream';
import { pipeline } from 'stream/promises';

const app = express();
const port = 3000;
const fallBackDomain = 'https://www.example.com';

let recentRequests = [];
const rateLimitWindow = 3000; // Time window for the requests to count in ms
const rateLimitCount = 10; // Max amount of allowed requests for that time window, inclusive

// Build using the specs given by https://datatracker.ietf.org/doc/html/rfc9110#name-http-related-uri-schemes
const urlRegName = /(?<regName>[\w~.\-!$&'()*+,;=%]+)/;
const ipv4Regex = /(?<ipv4Address>(?:25[0-5]|2[0-4]\d|1?\d{1,2})(?:\.25[0-5]|\.2[0-4]\d|\.1?\d{1,2}){3})/;
const ipv6Regex = (endingChar = '[^\\da-f:.]') => {
  //ls32 = ( h16 ":" h16 ) / IPv4address        # least-significant 32 bits of address
  //h16 = 1*4HEX_DIGIT            # 16 bits of address represented in hexadecimal
  const ls32 = `(?:${/[\da-f]{1,4}:[\da-f]{1,4}/.source}|${ipv4Regex.source.replace('<ipv4Address>', ':')})`;

  // Counts the total number of h16 groups up until and including the first bit of the ls32 and asserts it at most 6.
  const countingLookahead = `(?=${/:*(?:[\da-f]{1,4}:+){0,5}[\da-f]{1,4}/.source}(?::[\\da-f]{1,4}${endingChar}|\\.))`;

  // (((group count check + 4-abbreviated group + 5-explicit group) OR 6-explicit group) + ls32) OR the two final cases manually
  return new RegExp(
    [
      `(?<ipv6Address>(?:${countingLookahead}`,
      `${/(?:(?:[\da-f]{1,4}:){1,5}|:):(?:[\da-f]{1,4}:){0,5}/.source}`, // [ *4( h16 ":" ) h16 ] "::" 5( h16 ":" )
      `|${/(?:[\da-f]{1,4}:){6}/.source})`, // 6( h16 ":" )
      ls32,
      `|${/(?:(?:[\da-f]{1,4}:){0,5}[\da-f]{1,4})?::[\da-f]{1,4}/.source}`, // [ *5( h16 ":" ) h16 ] "::" h16
      `|${/(?:(?:[\da-f]{1,4}:){0,6}[\da-f]{1,4})?::/.source})`, // [ *6( h16 ":" ) h16 ] "::"
      `(?=${endingChar})`,
    ].join(''),
    'i',
  );
};
const ipvFutureRegex = /(?<ipvFuture>v[\da-fA-F]+\.[\w~.\-!$&'()*+,;=:]+)/;

const urlProtocolRegex = /(?<protocol>https?:)/i;
const urlEscapedDelimiterRegex = /(?<delimiter>\/|\\\/|\\u002f)/i;
const urlUserInfoRegex = /(?<userInfo>[\w~.\-!$&'()*+,;=%:]*@)/;
const urlHostRegex = new RegExp(
  [
    `(?<host>`,
    `\\[${ipv6Regex(']').source}\\]|`, // Ipv6 literal
    `\\[${ipvFutureRegex.source}\\]|`, // IpvFuture literal
    `${ipv4Regex.source}|`, // Ipv4 address
    `${urlRegName.source})`, // Reg name
  ].join(''),
  '',
);

/\[[\w~.\-!$&'()*+,;=:]{2,}\]|[\w~.\-!$&'()*+,;=%]+/;
const urlPortRegex = /(?<port>:\d*)/;
const urlPathRegexSource = (delimiter = '/') => `(?<path>(?:${delimiter}[\\w~.\\-!$&'()*+,;=%:@]*)*)`;
const urlQueryRegex = /(?<query>\?[\w~.\-!$&'()*+,;=%:@/?]*)/;
const urlFragmentRegex = /(?<fragment>#[\w~.\-!$&'()*+,;=%:@/?]*)/;

const urlReplacementRegex = new RegExp(
  [
    // May not be preceded by a backslash or part of the xmlns attribute
    `${/(?<!\\|xmlns\s*=\s*\S{0,6})/.source}`,
    `${urlProtocolRegex.source}?`,
    `${urlEscapedDelimiterRegex.source}\\k<delimiter>`,
    `${urlUserInfoRegex.source}?${urlHostRegex.source}${urlPortRegex.source}?`,
    `${urlPathRegexSource('\\k<delimiter>')}`,
    `${urlQueryRegex.source}?`,
    `${urlFragmentRegex.source}?`,
  ].join(''),
  'gi',
);

const urlValidationRegex = new RegExp(
  [
    `^${urlProtocolRegex.source}//`,
    `${urlUserInfoRegex.source}?${urlHostRegex.source}${urlPortRegex.source}?`,
    `${urlPathRegexSource('/')}`,
    `${urlQueryRegex.source}?`,
    `${urlFragmentRegex.source}?$`,
  ].join(''),
  'i',
);

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
 * Parses a cookie string according to the cookie specifications found here:
 * https://datatracker.ietf.org/doc/html/rfc6265, section 5.2
 *
 * The cookie, when valid, is returned as an object with the attributes name, value, options.
 * Options itself is another object containing the options that came with the cookies.
 * All option keys are lower cased except 'httpOnly', 'maxAge' and 'sameSite'.
 * If the cookie string is syntactically invalid, undefined is retuned.
 *
 * @param {string} cookie The cookie string to parse.
 * @returns {{name: string, value: string, options: Object}|undefined} The parsed cookie.
 */
function parseCookie(cookie) {
  const nameValueRegex = /\s*(?<name>[^\s;=][^;=]*)=(?<value>[^;]*)/;
  const cookieAttrRegex = /;(?<attrName>[^;=]*)(?:=(?<attrValue>[^;]+))?/g;
  const cookieRegex = new RegExp(`^${nameValueRegex.source}(?:${cookieAttrRegex.source})*$`, '');

  const nameValue = cookie.match(cookieRegex);
  if (!nameValue) return undefined;

  const options = Object.fromEntries(
    cookie.matchAll(cookieAttrRegex).map((attrMatch) => {
      // cSpell: disable
      const attrName = attrMatch[1]
        .trim()
        .toLowerCase()
        .replace('samesite', 'sameSite')
        .replace('httponly', 'httpOnly');
      // cSpell: enable
      if (!attrMatch[2]) return [attrName, true];

      const attrValue = attrMatch[2].trim();
      // cspell: disable-next-line
      if (attrName === 'maxage') return ['maxAge', Number.parseInt(attrValue)];
      if (attrName === 'expires') return ['expires', new Date(attrValue)];
      return [attrName, attrValue];
    }),
  );
  return { name: nameValue[1].trim(), value: nameValue[2].trim(), options };
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
    // Headers lower-cased by express
    switch (name) {
      case 'host':
      case 'origin':
        resultHeaders.set(name, proxyTarget);
        break;
      case 'content-length':
      case 'content-encoding':
      case 'transfer-encoding':
        break;
      case 'cookie': {
        const cookies = value
          .split(';')
          .map((c) => {
            const trimmed = c.trim();
            const cookieName = trimmed.substring(0, trimmed.indexOf('='));
            if (cookieName === 'proxyTargets') return '';
            if (cookieName.search(/^_+proxyTargets$/) !== -1) return trimmed.substring(1);
            return trimmed;
          })
          .filter((c) => c !== '')
          .join('; ');

        resultHeaders.set(name, cookies);
        break;
      }
      default:
        resultHeaders.set(name, value);
        break;
    }
  });

  return resultHeaders;
}

/**
 * Transforms the headers that are received from the proxy target to so that they
 * are usable to send to the browser. Modifies the response instead of returning anything.
 *
 * @param {Response} proxyResponse The response from the proxy target
 * @param {Express.Response} res The response to send to the browser
 * @param {string} proxyTarget The proxy target
 */
function transformHeadersForResponse(proxyResponse, res, proxyTarget) {
  for (const [name, value] of proxyResponse.headers) {
    // Headers lower-cased by mdn reference
    switch (name) {
      case 'set-cookie': {
        const parsedCookie = parseCookie(value);
        if (!parsedCookie) break;

        if (parsedCookie.options.domain) {
          parsedCookie.options.domain = proxyTarget.split(':')[0];
        }
        if (parsedCookie.name.search(/^_*proxyTargets$/) !== -1) {
          parsedCookie.name = '_' + parsedCookie.name;
        }
        parsedCookie.options.encode = String;
        res.cookie(parsedCookie.name, parsedCookie.value, parsedCookie.options);
        break;
      }
      case 'content-security-policy':
      case 'content-security-policy-report-only':
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
      case 'transfer-encoding':
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
  let result = html.replace(urlReplacementRegex, (...args) => {
    const groups = args.at(-1);
    const replacement = [
      `http:${groups.delimiter.repeat(2)}${proxyDomain}`,
      `${groups.delimiter}`,
      `${groups.protocol?.replace(':', '.') || 'http.'}${groups.userInfo || ''}${groups.host}${groups.port || ''}`,
      `${groups.path || ''}`,
      `${groups.query || ''}`,
      `${groups.fragment || ''}`,
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

  // Url validation
  if ((proxyTarget + url).search(urlValidationRegex) === -1) throw new Error('Not a valid url: ' + (proxyTarget + url));

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
  if (req.url.startsWith('/http.') || req.url.startsWith('/https.')) {
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
  console.log(`CSP violation: ${JSON.stringify(req.body, undefined, 2)}`);
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
    transformHeadersForResponse(response, res, host);
    res.cookie('proxyTargets', JSON.stringify(req.cookies.proxyTargets), {
      httpOnly: true,
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
      await pipeline(Readable.fromWeb(response.body), res).catch(console.log);
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
