import express from 'express';

const app = express();
const port = 3000;
const defaultBrowser = 'https://www.startpage.com';

/**
 * Extracts the proxy target from the first part of the url. The proxy target will be returned raw,
 * but also if the first part starts with 'http.' or 'https.', then the dot will be replaced with '://'.
 * This processed proxy with then be returned as well. Finally, the rest of the url will be returned.
 * For example: '/https.example.com/some/url' => ['https.example.com', 'https://example.com', '/some/url'].
 * @param {string} url The url to split up.
 * @return {[string, string, string]} The raw proxy target, processed proxy target and remaining url in that order.
 */
function extractProxyTarget(url) {
  if (url == '/') return [defaultBrowser.replace('://', '.'), defaultBrowser, '/'];

  const parts = url.substring(1).split('/');
  const rawProxyTarget = parts.shift();
  let processedProxyTarget = rawProxyTarget;
  if (processedProxyTarget.startsWith('http.') || processedProxyTarget.startsWith('https.'))
    processedProxyTarget = processedProxyTarget.replace('.', '://');

  return [rawProxyTarget, processedProxyTarget, '/' + parts.join('/')];
}

/**
 * Transfers http headers from a list and extracts the relevant ones,
 * and potentially modifies them, to return them as a new object.
 * @param {Object.<string, string> | Headers} source The source map of headers.
 * @param {string} pretendDomainSource The source domain the headers should pretend by.
 * @returns {Object.<string, string>} The transferred headers.
 */
function transferHeaders(source, _pretendDomainSource) {
  let s = {};
  if (source instanceof Headers) {
    source.forEach((value, key) => (s[key] = value));
  } else {
    s = source;
  }

  let result = {};
  if (s['accept']) result['accept'] = s['accept'];
  if (s['accept-encoding']) result['accept-encoding'] = s['accept-encoding'];
  if (s['accept-language']) result['accept-language'] = s['accept-language'];
  if (s['accept-ranges']) result['accept-ranges'] = s['accept-ranges'];
  if (s['age']) result['age'] = s['age'];
  if (s['cache-control']) result['cache-control'] = s['cache-control'];
  if (s['connection']) result['connection'] = s['connection'];
  if (s['date']) result['date'] = s['date'];
  if (s['user-agent']) result['user-agent'] = s['user-agent'];
  if (s['content-security-policy'])
    // result['content-security-policy'] = replaceDomain(s['content-security-policy'], pretendDomainSource);
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
      'report-uri http://localhost:' +
      port;

  return result;
}

/**
 * Tries to inject the proxy target into all forms of url of the given html.
 * It generally matches these patterns, also taking \u002F into account:
 *    '/some/url' => '/<rawProxyTarget>/some/url'
 *    'http(s)://www.some.domain/path' => '/http(s).www.some.domain/path'
 * @param {string} html The html string.
 * @param {string} rawProxyTarget The raw proxy target.
 * @returns The resulting string
 */
function injectProxyTargetHtml(html, rawProxyTarget) {
  let result = html.replace(/([ `'"(])(\/|\\u002f)(\w)/gi, `$1$2${rawProxyTarget}$2$3`);
  return result.replace(/(https?):(\/|\\u002f){2}/gi, '$2$1.');
}

/**
 * Tries to inject the proxy target into all forms of url of the given css.
 * It generally matches these patterns:
 *    '/some/url' => '/<rawProxyTarget>/some/url'
 *    'http(s)://www.some.domain/path' => '/http(s).www.some.domain/path'
 * @param {string} css The css string.
 * @param {string} rawProxyTarget The raw proxy target.
 * @returns The resulting string
 */
function injectProxyTargetCss(css, rawProxyTarget) {
  let result = css.replace(/([ `'"(])(\/|\\u002f)(\w)/gi, `$1$2${rawProxyTarget}$2$3`);
  return result.replace(/(https?):(\/|\\u002f){2}/gi, '$2$1.');
}

/**
 * Tries to inject the proxy target into all forms of url of the given js.
 * It generally matches these patterns:
 *    'fetch(someUrl' => 'fetch('/<rawProxyTarget>'+someUrl'
 * @param {string} html The html string.
 * @param {string} rawProxyTarget The raw proxy target.
 * @returns The resulting string
 */
function injectProxyTargetJs(js, rawProxyTarget) {
  return js.replace(/fetch\(\s*?([`'"\w])/g, `fetch('/${rawProxyTarget}'+$1`);
}

/**
 * If the head of the given html document contains a link tag for the icon,
 * no modifications are made. Otherwise, a link tag for the icon is injected
 * referencing '/<rawProxyTarget>/favicon.ico' with the given raw proxy target
 * to overwrite the default '/favicon.ico' reference which the proxy has no control over.
 * @param {string} html The html to inject the link tag into.
 * @param {string} rawProxyTarget The raw proxy target to inject.
 * @return {string} The new html document.
 */
function injectFavIcon(html, rawProxyTarget) {
  const parts = html.split('</head>', 2);
  if (parts[0].search(/<link.+?rel\s*?=\s*?['"]?icon['"]?.*?\/?>/i) !== -1) return html;
  return `${parts[0]}<link rel=icon href="/${rawProxyTarget}/favicon.ico"/></head>${parts[1]}`;
}

/*
 * Get requests
 */
app.get('/**', async (req, res, next) => {
  try {
    // console.log(req);

    const [rawProxyTarget, proxyTarget, url] = extractProxyTarget(req.url);
    const response = await fetch(proxyTarget + url, {
      method: 'GET',
      headers: transferHeaders(req.headers, req.host),
    });

    let body = await response.text();
    const type = response.headers.get('content-type');
    if (type.startsWith('text/html')) {
      body = injectProxyTargetHtml(body, rawProxyTarget);
      body = injectFavIcon(body, rawProxyTarget);
    }
    if (type.startsWith('text/css')) body = injectProxyTargetCss(body, rawProxyTarget);
    if (type.startsWith('text/javascript') || type.startsWith('application/javascript'))
      body = injectProxyTargetJs(body, rawProxyTarget);

    // console.log(result);
    res.type(type);
    res.status(response.status);
    res.set(transferHeaders(response.headers, req.host));
    // res.type('text');
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
