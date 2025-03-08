const express = require("express");
const app = express();
const port = 3000;
const proxyTarget = "https://www.nytimes.com";

/**
 * Transfers http headers from a list and extracts the relevant ones,
 * and potentially modifies them, to return them as a new object.
 * @param {Object.<string, string> | Headers} source The source map of headers.
 * @param {string} pretendDomainSource The source domain the headers should pretend by.
 * @returns {Object.<string, string>} The transferred headers.
 */
function transferHeaders(source, pretendDomainSource) {
  let s = {};
  if (source instanceof Headers) {
    source.forEach((value, key) => (s[key] = value));
  } else {
    s = source;
  }

  let result = {};
  if (s["accept"]) result["accept"] = s["accept"];
  if (s["accept-encoding"]) result["accept-encoding"] = s["accept-encoding"];
  if (s["accept-language"]) result["accept-language"] = s["accept-language"];
  if (s["accept-ranges"]) result["accept-ranges"] = s["accept-ranges"];
  if (s["age"]) result["age"] = s["age"];
  if (s["cache-control"]) result["cache-control"] = s["cache-control"];
  if (s["connection"]) result["connection"] = s["connection"];
  if (s["date"]) result["date"] = s["date"];
  if (s["user-agent"]) result["user-agent"] = s["user-agent"];
  if (s["content-security-policy"])
    // result['content-security-policy'] = replaceDomain(s['content-security-policy'], pretendDomainSource);
    result["content-security-policy"] =
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
      "report-uri http://localhost:" +
      port;

  return result;
}

/**
 * Replaces all instances of proxy target in the given string with the specified host,
 * the port is automatically appended to the host including the colon. This function takes
 * '\u002F' into account and tries to preserve them if applicable.
 * @param {string} source The source string to replace.
 * @param {string} value The string to replace with.
 * @returns {string} The resulting string.
 */
function replaceDomain(source, value) {
  const val = "http://" + value + ":" + port;
  let result = source.replaceAll(proxyTarget, val);
  result = result.replaceAll(
    proxyTarget.replaceAll("/", "\\u002F"),
    val.replaceAll("/", "\\u002F"),
  );
  result = result.replaceAll("https://csp.nytimes.com", val);
  return result;
}

app.get("/**", async (req, res) => {
  // console.log(req);

  let response;
  try {
    response = await fetch(proxyTarget + req.url, {
      method: "GET",
      headers: transferHeaders(req.headers, req.host),
    });
  } catch (error) {
    console.log(error.message);
  }

  let result = await response.text();
  result = replaceDomain(result, req.host);
  const type = response.headers.get("content-type");

  // console.log(result);
  res.type(type);
  res.status(response.status);
  res.set(transferHeaders(response.headers, req.host));
  // res.type('text');
  res.send(result);
});

app.use("/**", (req, res) => {
  console.log("got here");
  res.status(501).send();
});

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
