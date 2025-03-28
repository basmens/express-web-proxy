import express from 'express';
import cookieParser from 'cookie-parser';
import { Readable } from 'stream';
import cookie from 'cookie';

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
 * Transforms the headers from browser requests so that they can be
 * used to send to the proxy target.
 *
 * @param {*} req The request from the browser.
 * @param {*} proxyTarget The proxy target
 * @returns [Headers] A Headers instance containing the transferred headers.
 */
function transformHeadersForRequest(req, proxyTarget) {
  let resultHeaders = new Headers();

  Object.entries(req.headers).forEach(([name, value]) => {
    switch (name) {
      case 'host':
      case 'origin':
        resultHeaders.set(name, proxyTarget);
        break;
      case 'content-security-policy':
        resultHeaders.set(
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
 * transform headers that are received from the proxy target to so that they
 * are usable to send to the browser.
 *
 * @param {*} proxyResponse The response from the proxy target
 * @param {*} res The response to send to the browser
 * @param {*} proxyTarget The proxy target
 */
function transformHeadersForResponse(proxyResponse, res, proxyTarget) {
  for (const [name, value] of proxyResponse.headers) {
    switch (name) {
      case 'host':
      case 'origin':
        res.set(name, proxyTarget);
        break;
      case 'set-cookie':
        {
          const cookieName = value.slice(0, value.indexOf('='));
          const parsedCookie = cookie.parse(value);
          const cookieValue = parsedCookie[cookieName];
          delete parsedCookie[cookieName];

          if (parsedCookie.expires) {
            parsedCookie.expires = new Date(parsedCookie.expires);
          }

          if (parsedCookie.domain) {
            parsedCookie.domain = proxyTarget.split(':')[0];
          }

          res.cookie(cookieName, cookieValue, parsedCookie);
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
        break;
      default:
        res.set(name, value);
        break;
    }
  }
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
app.post('/debug/csp', (req, res) => {
  console.log(`CSP violation while proxying ${req.cookies.proxyTarget}: ${req.body}`);
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
    const bodyStream = ['GET', 'HEAD', 'TRACE'].includes(req.method) ? undefined : Readable.toWeb(req);
    const proxyTargetResponse = await fetch(req.proxyTarget + req.url, {
      method: req.method,
      headers: transformHeadersForRequest(req, req.proxyTarget.split('://')[1]),
      body: bodyStream,
      duplex: 'half',
    });

    transformHeadersForResponse(proxyTargetResponse, res, req.headers.host);

    res.status(proxyTargetResponse.status);

    const type = proxyTargetResponse.headers.get('content-type');
    if (!type) {
      res.send();
      return;
    }

    if (
      req.method === 'GET' &&
      proxyTargetResponse.status >= 200 &&
      proxyTargetResponse.status <= 299 &&
      type.includes('html')
    ) {
      res.cookie('proxyTarget', req.proxyTarget, { maxAge: 9000000000, httpOnly: false, secure: true });
    }

    if (
      type.includes('html') ||
      type.includes('css') ||
      type.includes('javascript') ||
      type.includes('json') ||
      type.includes('text')
    ) {
      res.send(injectProxyTarget(await proxyTargetResponse.text(), req.headers.host));
    } else {
      res.setHeader('content-length', proxyTargetResponse.headers.get('content-length'));
      Readable.fromWeb(proxyTargetResponse.body).pipe(res);
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
