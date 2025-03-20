import express from 'express';
import cookieParser from 'cookie-parser';

const app = express();
const port = 3000;
const defaultBrowser = 'https://www.example.com';

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
  const urlRegex = /(?:(https?):)?(\/|\\u002f){2}([^"<\s?]*)([^"<\s]*)/gi;

  return html.replace(urlRegex, (_full, protocol, delimiter, path, query) => {
    return `http:${delimiter.repeat(2)}${proxyDomain}${delimiter}${protocol ? protocol : 'http'}.${path}${query}`;
  });
}

app.use(cookieParser());
app.use(express.text({ type: '*/*' }));

app.post('/debug/csp', (req, res) => {
  console.log(`CSP violation while proxying ${req.cookies.proxyTarget}: ${req.body}`);
  res.status(200).send();
});

app.use((req, res, next) => {
  if (!req.proxyTarget) doProxyTargeting(req);
  if (req.proxyTarget.includes(req.host)) doProxyTargeting(req); // Try again
  next();
});

app.all('/**', async (req, res, next) => {
  try {
    const host = req.headers.host; // This includes the port
    if ('GET HEAD TRACE'.includes(req.method) || Object.keys(req.body).length === 0) req.body = undefined;
    const response = await fetch(req.proxyTarget + req.url, {
      method: req.method,
      headers: transferHeaders(req.headers, host, req.proxyTarget.split('://')[1]),
      body: req.body,
    });

    res.status(response.status);
    res.set(transferHeaders(response.headers, host, host));

    const type = response.headers.get('content-type');
    if (!type) {
      res.send();
      return;
    }

    if (req.method === 'GET' || type.includes('html'))
      res.cookie('proxyTarget', req.proxyTarget, { maxAge: 9000000000, httpOnly: false, secure: true });

    let body;
    if (type.includes('html') || type.includes('css') || type.includes('javascript')) {
      body = injectProxyTarget(await response.text(), host);
    } else {
      body = Buffer.from(await (await response.blob()).arrayBuffer());
    }
    res.send(body);
  } catch (err) {
    next(err);
  }
});

app.use('/**', (req, res) => {
  console.log('got here');
  res.status(501).send();
});

app.use((err, req, res, _next) => {
  console.log(err);
  res.status(500).send(err);
});

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
