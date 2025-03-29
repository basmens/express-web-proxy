import express from 'express';
import cookieParser from 'cookie-parser';
import { Readable } from 'stream';

const app = express();
const port = 3000;
const defaultBrowser = 'https://www.example.com';

let recentRequests = [];
const rateLimitWindow = 3000; // Time window for the requests to count in ms
const rateLimitCount = 2; // Max amount of allowed requests for that time window, inclusive

/**
 * Takes the req and finds the list of possible proxy targets. The first element is the most likely target,
 * the second a fallback if the first one fails, the third if the second one fails etc. The list comes in
 * string number pairs, each time the proxy target and the index in the list in the cookie that is associated with
 * that index, so that if the proxy target turns out to be the one responsible for a successful result, then
 * all elements up until but not including the index can be removed from the list in the cookie. A -1 value
 * is not in the cookies list and should be ignored for that purpose. Further, because the url may need to
 * have bits cut out, the new url is returned too.
 * @param {Request} req The req.
 * @returns {[Array<{proxyTarget: string, cookieListIndex: number}>, string]} A list of proxy targets in most likely order together with their
 * index in the list in the cookie or -1 if not in the list. Finally, also the potentially modified url is returned.
 */
function getProxyTargets(req) {
  if (req.url.startsWith('/http')) {
    const parts = req.url.substring(1).split('/');
    const proxyTarget = parts.shift().replace('.', '://');
    return [[{ proxyTarget: proxyTarget, cookieListIndex: -1 }], '/' + parts.join('/')];
  }

  if (req.cookies.proxyTargets.length > 0) {
    const proxyTargets = [];
    for (const [index, proxyTarget] of req.cookies.proxyTargets.entries()) {
      if (proxyTargets.find((e) => e.proxyTarget === proxyTarget)) continue;
      proxyTargets.push({ proxyTarget: proxyTarget, cookieListIndex: index });
    }
    return [proxyTargets, req.url];
  }

  return [[{ proxyTarget: defaultBrowser, cookieListIndex: -1 }], '/'];
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
  const urlRegex = /(^|[^\\])(?:(https?):)?(\/|\\u002f){2}([^"<\s?]*)([^"<\s]*)/gi;

  return html.replace(urlRegex, (_full, charBefore, protocol, delimiter, path, query) => {
    const [firstProtocol, secondProtocol] = protocol ? ['http:', protocol] : ['', 'http'];
    return `${charBefore}${firstProtocol}${delimiter.repeat(2)}${proxyDomain}${delimiter}${secondProtocol}.${path}${query}`;
  });
}

/**
 * Checks if a req on a given proxy target has exceeded the rate limit.
 * @param {express.Request} req The req to check for rate limiting.
 * @param {string} proxyTarget The proxy target.
 * @param {string} path The path of the request
 * @returns {boolean} True if rate limit is exceeded, false otherwise.
 */
function checkRateLimit(req, proxyTarget, path) {
  const now = new Date().getTime();
  recentRequests.push({
    ip: req.ip,
    'user-agent': req.headers['user-agent'],
    proxyTarget: proxyTarget,
    path: path,
    time: now,
  });

  while (recentRequests.length > 0 && now - recentRequests[0].time > rateLimitWindow) recentRequests.shift();

  let count = 0;
  for (const r of recentRequests) {
    if (
      r.ip === req.ip &&
      r['user-agent'] === req.headers['user-agent'] &&
      r.proxyTarget === proxyTarget &&
      r.path === path
    )
      count++;
  }
  return count > rateLimitCount;
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
    const [proxyTargetsToAttempt, url] = getProxyTargets(req);
    if (!proxyTargetsToAttempt || proxyTargetsToAttempt.length === 0) throw new Error('No proxy targets given');

    const cookieProxyTargets = req.cookies.proxyTargets;
    const path = url.split('?', 2)[0];
    const host = req.headers.host; // This includes the port
    let bodyStream = ['GET', 'HEAD', 'TRACE'].includes(req.method) ? undefined : Readable.toWeb(req);

    // Go through possible proxy targets until a successful response is found
    let response;
    let proxyTargetEntry;
    for (proxyTargetEntry of proxyTargetsToAttempt) {
      // Rate limit
      const proxyTarget = proxyTargetEntry.proxyTarget;
      if (checkRateLimit(req, proxyTarget, path)) {
        res.status(429).send();
        return;
      }

      // Send request
      let streamTee;
      if (bodyStream) [bodyStream, streamTee] = bodyStream.tee();

      const newResponse = await fetch(proxyTarget + url, {
        method: req.method,
        headers: transferHeaders(req.headers, host, proxyTarget.split('://')[1]),
        body: streamTee,
        duplex: 'half',
      });

      if (!response) response = newResponse;
      if (newResponse.status < 400) {
        response = newResponse;
        break;
      }
    }
    const proxyTarget = proxyTargetEntry.proxyTarget;
    const proxyTargetCookieIndex = proxyTargetEntry.cookieListIndex;

    // Remove the proxy targets that were set incorrectly or previous one is used now
    if (response.status >= 200 && response.status <= 299 && proxyTargetCookieIndex > 0) {
      cookieProxyTargets.splice(0, proxyTargetCookieIndex);
      res.cookie('proxyTargets', JSON.stringify(cookieProxyTargets), {
        maxAge: 9000000000,
        httpOnly: false,
        secure: true,
      });
    }

    res.status(response.status);
    res.set(transferHeaders(response.headers, host, host));

    // Handle requests without a type simply
    const type = response.headers.get('content-type');
    if (!type) {
      res.send();
      return;
    }

    // Add new proxy target to the list if applicable
    if (
      response.status >= 200 &&
      response.status <= 299 &&
      req.method === 'GET' &&
      type.includes('html') &&
      proxyTargetCookieIndex === -1 &&
      (cookieProxyTargets.length === 0 || cookieProxyTargets[0] !== proxyTarget)
    ) {
      cookieProxyTargets.unshift(proxyTarget);
      res.cookie('proxyTargets', JSON.stringify(cookieProxyTargets), {
        maxAge: 9000000000,
        httpOnly: false,
        secure: true,
      });
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
