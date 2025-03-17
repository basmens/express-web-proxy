import express from 'express';
import cookieParser from 'cookie-parser';

const app = express();
const port = 3000;
const defaultBrowser = 'https://www.startpage.com';

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
 * @returns The resulting string.
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
 * @returns The resulting string.
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
 * @returns The resulting string.
 */
function injectProxyTargetJs(js, rawProxyTarget) {
  return js.replace(/fetch\(\s*?([`'"\w])/g, `fetch('/${rawProxyTarget}'+$1`);
}

app.use(cookieParser());
app.use((req, res, next) => {
  if (!req.proxyTarget) doProxyTargeting(req);
  next();
});

/*
 * Get requests
 */
app.get('/**', async (req, res, next) => {
  try {
    const response = await fetch(req.proxyTarget + req.url, {
      method: 'GET',
      headers: transferHeaders(req.headers, req.proxyTarget.split('://')[1]),
    });

    res.status(response.status);
    res.set(transferHeaders(response.headers, req.host));

    const type = response.headers.get('content-type');
    if (!type) {
      res.send();
      return;
    }

    let body;
    const rawProxyTarget = req.proxyTarget.replace('://', '.');
    if (type.includes('html')) {
      body = injectProxyTargetHtml(await response.text(), rawProxyTarget);
      res.cookie('proxyTarget', req.proxyTarget, { maxAge: 9000000000, httpOnly: false, secure: true });
    } else if (type.includes('css')) {
      body = injectProxyTargetCss(await response.text(), rawProxyTarget);
    } else if (type.includes('javascript')) {
      body = injectProxyTargetJs(await response.text(), rawProxyTarget);
    } else {
      body = Buffer.from(await (await response.blob()).arrayBuffer());
    }

    res.type(type);
    res.send(body);
  } catch (err) {
    next(err);
  }
});

/*
 * Post requests
 */
app.post('/**', async (req, res, next) => {
  try {
    const response = await fetch(req.proxyTarget + req.url, {
      method: 'POST',
      headers: transferHeaders(req.headers, req.proxyTarget.split('://')[1]),
    });

    res.status(response.status);
    res.set(transferHeaders(response.headers, req.host));

    const type = response.headers.get('content-type');
    if (!type) {
      res.send();
      return;
    }

    let body;
    const rawProxyTarget = req.proxyTarget.replace('://', '.');
    if (type.includes('html')) {
      body = injectProxyTargetHtml(await response.text(), rawProxyTarget);
    } else if (type.includes('css')) {
      body = injectProxyTargetCss(await response.text(), rawProxyTarget);
    } else if (type.includes('javascript')) {
      body = injectProxyTargetJs(await response.text(), rawProxyTarget);
    } else {
      (await response.blob()).arrayBuffer().then((buf) => {
        body = Buffer.from(buf);
      });
    }

    res.type(type);
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
