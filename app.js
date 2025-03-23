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
 * Takes the req and finds the proxy target. It modifies the req to set the url to the url without
 * any proxy targeting included. The req gains a proxyTarget attribute.
 * @param {Request} req The req.
 */
function doProxyTargeting(req) {
  if (req.url.startsWith('/http')) {
    const parts = req.url.substring(1).split('/');
    req.proxyTarget = parts.shift().replace('.', '://');
    req.url = '/' + parts.join('/');
    return;
  }

  if (req.cookies.proxyTarget) {
    req.proxyTarget = req.cookies.proxyTarget;
    return;
  }

  req.proxyTarget = defaultBrowser;
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
 * @returns The resulting string.
 */
function injectProxyTarget(html, proxyDomain) {
  const urlRegex = /(?:(https?):)(\/|\\u002f){2}([^"<\s?]*)([^"<\s]*)/gi;

  return html.replace(urlRegex, (_full, protocol, delimiter, path, query) => {
    return `http:${delimiter.repeat(2)}${proxyDomain}${delimiter}${protocol ? protocol : 'http'}.${path}${query}`;
  });
}

/*
 * Parse cookies and body
 */
app.use(cookieParser());

/*
 * Content security endpoint for debugging
 */
app.post('/debug/csp', async (req, res) => {
  const bodyAsJson = await new Promise((resolve, _reject) => {
    let result = '';
    req.on('readable', () => {
      let chunk;

      while (null !== (chunk = req.read())) {
        result = result + chunk;
      }
    });

    req.on('end', () => {
      resolve(result);
    });
  });

  const body = JSON.parse(bodyAsJson);

  console.log(`CSP violation while proxying ${req.cookies.proxyTarget}: ${JSON.stringify(body, undefined, '  ')}`);
  res.status(200).send();
});

/*
 * Infer proxy target
 */
app.use((req, res, next) => {
  if (!req.proxyTarget) doProxyTargeting(req);
  if (req.proxyTarget.includes(req.host)) doProxyTargeting(req); // Try again
  next();
});

/*
 * Do rate limiting
 */
app.all('/**', (req, res, next) => {
  const now = new Date().getTime();
  recentRequests.push({
    ip: req.ip,
    'user-agent': req.headers['user-agent'],
    proxyTarget: req.proxyTarget,
    path: req.path,
    time: now,
  });

  while (recentRequests.length > 0 && now - recentRequests[0].time > rateLimitWindow) recentRequests.shift();

  let count = 0;
  for (const r of recentRequests) {
    if (
      r.ip === req.ip &&
      r['user-agent'] === req.headers['user-agent'] &&
      r.proxyTarget === req.proxyTarget &&
      r.path === req.path
    )
      count++;
  }

  if (count > rateLimitCount) {
    res.status(429).send();
    return;
  }
  next();
});

/*
 * Proxy requests
 */
app.all('/**', async (req, res, next) => {
  try {
    const host = req.headers.host; // This includes the port
    const bodyStream = ['GET', 'HEAD', 'TRACE'].includes(req.method) ? undefined : Readable.toWeb(req);
    const response = await fetch(req.proxyTarget + req.url, {
      method: req.method,
      headers: transferHeaders(req.headers, host, req.proxyTarget.split('://')[1]),
      body: bodyStream,
      duplex: 'half',
    });

    res.status(response.status);
    res.set(transferHeaders(response.headers, host, host));

    const type = response.headers.get('content-type');
    if (!type) {
      res.send();
      return;
    }

    if (req.method === 'GET' && response.status >= 200 && response.status <= 299 && type.includes('html'))
      res.cookie('proxyTarget', req.proxyTarget, { maxAge: 9000000000, httpOnly: false, secure: true });

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
