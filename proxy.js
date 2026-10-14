// Local relay between the sidebar's iframe and the T3 Code server.
//
// The T3 web app runs in a cross-origin iframe inside a webview, where Cmd+V
// never reaches the page and the session cookie (SameSite=Lax) is not sent.
// The relay fixes both: it injects a small script that routes clipboard
// shortcuts through the extension, and it keeps the session cookie itself.
//
// Because the relay attaches your T3 session to requests, it only serves
// requests from the sidebar: same-origin requests from the page itself, plus
// the initial iframe load, which must carry a per-process launch token.

"use strict";

const http = require("node:http");
const crypto = require("node:crypto");

const LAUNCH_PARAM = "__t3sidebar";
const SHIM_PATH = "/__t3sidebar/shim.js";

const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

class CookieJar {
  constructor(serialized, onChange) {
    this.cookies = new Map();
    this.onChange = onChange;
    try {
      for (const [name, entry] of Object.entries(JSON.parse(serialized || "{}"))) {
        this.cookies.set(name, entry);
      }
    } catch {
      // Start empty if the stored jar is unreadable.
    }
  }

  update(setCookieHeaders) {
    if (!setCookieHeaders || setCookieHeaders.length === 0) return;
    for (const header of setCookieHeaders) {
      const [pair, ...attributes] = header.split(";");
      const separator = pair.indexOf("=");
      if (separator <= 0) continue;
      const name = pair.slice(0, separator).trim();
      const value = pair.slice(separator + 1).trim();
      let expires = null;
      for (const attribute of attributes) {
        const [key, ...rest] = attribute.split("=");
        const attributeValue = rest.join("=").trim();
        if (key.trim().toLowerCase() === "max-age") {
          expires = Date.now() + Number(attributeValue) * 1000;
        } else if (key.trim().toLowerCase() === "expires" && expires === null) {
          const parsed = Date.parse(attributeValue);
          if (!Number.isNaN(parsed)) expires = parsed;
        }
      }
      if (value === "" || (expires !== null && expires <= Date.now())) {
        this.cookies.delete(name);
      } else {
        this.cookies.set(name, { value, expires });
      }
    }
    this.onChange?.(this.serialize());
  }

  header() {
    const now = Date.now();
    const pairs = [];
    for (const [name, { value, expires }] of this.cookies) {
      if (expires === null || expires > now) pairs.push(`${name}=${value}`);
    }
    return pairs.join("; ");
  }

  clear() {
    this.cookies.clear();
    this.onChange?.(this.serialize());
  }

  serialize() {
    return JSON.stringify(Object.fromEntries(this.cookies));
  }
}

class Relay {
  /**
   * @param {object} options
   * @param {() => URL} options.getTarget  T3 server origin to forward to.
   * @param {CookieJar} options.jar
   * @param {() => string} options.shim    JavaScript injected into HTML pages.
   * @param {(line: string) => void} [options.log]
   */
  constructor({ getTarget, jar, shim, log }) {
    this.getTarget = getTarget;
    this.jar = jar;
    this.shim = shim;
    this.log = log ?? (() => {});
    this.launchToken = crypto.randomBytes(24).toString("hex");
    this.server = null;
    this.port = 0;
  }

  get origin() {
    return `http://127.0.0.1:${this.port}`;
  }

  /** URL for the iframe, carrying the launch token. `pathAndHash` like "/pair#token=…". */
  launchUrl(pathAndHash = "/") {
    const url = new URL(pathAndHash, this.origin);
    url.searchParams.set(LAUNCH_PARAM, this.launchToken);
    return url.toString();
  }

  async start(firstPort, attempts = 10) {
    for (let port = firstPort; port < firstPort + attempts; port++) {
      try {
        await this.#listen(port);
        this.port = port;
        this.log(`relay listening on ${this.origin}`);
        return;
      } catch (cause) {
        if (cause.code !== "EADDRINUSE") throw cause;
        this.log(`port ${port} busy, trying the next one`);
      }
    }
    throw new Error(`No free relay port in ${firstPort}-${firstPort + attempts - 1}.`);
  }

  #listen(port) {
    return new Promise((resolve, reject) => {
      const server = http.createServer((req, res) => this.#handle(req, res));
      server.on("upgrade", (req, socket, head) => this.#handleUpgrade(req, socket, head));
      server.once("error", reject);
      server.listen(port, "127.0.0.1", () => {
        server.off("error", reject);
        this.server = server;
        resolve();
      });
    });
  }

  dispose() {
    this.server?.close();
    this.server?.closeAllConnections?.();
    this.server = null;
  }

  #hostAllowed(req) {
    const host = req.headers.host;
    return host === `127.0.0.1:${this.port}` || host === `localhost:${this.port}`;
  }

  #hasLaunchToken(url) {
    const presented = url.searchParams.get(LAUNCH_PARAM);
    if (presented === null) return false;
    const a = Buffer.from(presented);
    const b = Buffer.from(this.launchToken);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  }

  #allowed(req, url) {
    if (!this.#hostAllowed(req)) return false;
    if (req.headers["sec-fetch-site"] === "same-origin") return true;
    return req.headers["sec-fetch-dest"] === "iframe" && this.#hasLaunchToken(url);
  }

  #forwardHeaders(req, target) {
    const headers = {};
    for (const [name, value] of Object.entries(req.headers)) {
      if (HOP_BY_HOP.has(name) || name === "cookie" || name === "host") continue;
      headers[name] = value;
    }
    headers.host = target.host;
    if (headers.origin) headers.origin = target.origin;
    if (typeof headers.referer === "string" && headers.referer.startsWith(this.origin)) {
      headers.referer = target.origin + headers.referer.slice(this.origin.length);
    }
    const cookie = this.jar.header();
    if (cookie) headers.cookie = cookie;
    return headers;
  }

  #handle(req, res) {
    const url = new URL(req.url, this.origin);
    if (!this.#allowed(req, url)) {
      this.log(`blocked ${req.method} ${url.pathname} site=${req.headers["sec-fetch-site"]}`);
      res.writeHead(403, { "content-type": "text/plain" }).end("Forbidden");
      return;
    }
    if (url.pathname === SHIM_PATH) {
      res
        .writeHead(200, {
          "content-type": "text/javascript; charset=utf-8",
          "cache-control": "no-store",
        })
        .end(this.shim());
      return;
    }
    url.searchParams.delete(LAUNCH_PARAM);

    const target = this.getTarget();
    const headers = this.#forwardHeaders(req, target);
    // Uncompressed responses so HTML can be rewritten; this is loopback traffic.
    headers["accept-encoding"] = "identity";

    const upstream = http.request(
      {
        hostname: target.hostname,
        port: target.port || 80,
        method: req.method,
        path: url.pathname + url.search,
        headers,
      },
      (upstreamRes) => this.#respond(upstreamRes, res, target),
    );
    upstream.on("error", (cause) => {
      this.log(`upstream error ${req.method} ${url.pathname}: ${cause.message}`);
      if (!res.headersSent) {
        res
          .writeHead(502, { "content-type": "text/html; charset=utf-8" })
          .end(unavailablePage(target.origin));
      } else {
        res.destroy();
      }
    });
    req.pipe(upstream);
  }

  #respond(upstreamRes, res, target) {
    this.jar.update(upstreamRes.headers["set-cookie"]);
    const headers = {};
    for (const [name, value] of Object.entries(upstreamRes.headers)) {
      if (HOP_BY_HOP.has(name) || name === "set-cookie" || name === "x-frame-options") continue;
      headers[name] = value;
    }
    const csp = headers["content-security-policy"];
    if (csp) {
      headers["content-security-policy"] = String(csp)
        .split(";")
        .filter((directive) => !/^\s*frame-ancestors\b/i.test(directive))
        .join(";");
    }
    if (typeof headers.location === "string" && headers.location.startsWith(target.origin)) {
      headers.location = this.origin + headers.location.slice(target.origin.length);
    }

    const isHtml = /text\/html/i.test(String(upstreamRes.headers["content-type"] ?? ""));
    if (!isHtml) {
      res.writeHead(upstreamRes.statusCode, upstreamRes.statusMessage, headers);
      upstreamRes.pipe(res);
      return;
    }
    const chunks = [];
    upstreamRes.on("data", (chunk) => chunks.push(chunk));
    upstreamRes.on("end", () => {
      const tag = `<script src="${SHIM_PATH}"></script>`;
      let html = Buffer.concat(chunks).toString("utf8");
      html = /<head[^>]*>/i.test(html)
        ? html.replace(/<head[^>]*>/i, (open) => open + tag)
        : tag + html;
      const body = Buffer.from(html, "utf8");
      delete headers.etag;
      headers["content-length"] = String(body.length);
      res.writeHead(upstreamRes.statusCode, upstreamRes.statusMessage, headers);
      res.end(body);
    });
  }

  #handleUpgrade(req, socket, head) {
    const origin = req.headers.origin;
    const sameOrigin =
      origin === this.origin || origin === `http://localhost:${this.port}`;
    if (!this.#hostAllowed(req) || !sameOrigin) {
      this.log(`blocked websocket origin=${origin}`);
      socket.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
      return;
    }
    const target = this.getTarget();
    const headers = this.#forwardHeaders(req, target);
    headers.connection = "Upgrade";
    headers.upgrade = req.headers.upgrade;

    const upstream = http.request({
      hostname: target.hostname,
      port: target.port || 80,
      method: req.method,
      path: req.url,
      headers,
    });
    upstream.on("upgrade", (upstreamRes, upstreamSocket, upstreamHead) => {
      const lines = [`HTTP/1.1 101 ${upstreamRes.statusMessage || "Switching Protocols"}`];
      for (let i = 0; i < upstreamRes.rawHeaders.length; i += 2) {
        lines.push(`${upstreamRes.rawHeaders[i]}: ${upstreamRes.rawHeaders[i + 1]}`);
      }
      socket.write(lines.join("\r\n") + "\r\n\r\n");
      if (upstreamHead.length > 0) socket.write(upstreamHead);
      if (head.length > 0) upstreamSocket.write(head);
      upstreamSocket.pipe(socket);
      socket.pipe(upstreamSocket);
      const destroyBoth = () => {
        socket.destroy();
        upstreamSocket.destroy();
      };
      socket.on("error", destroyBoth);
      upstreamSocket.on("error", destroyBoth);
      socket.on("close", destroyBoth);
      upstreamSocket.on("close", destroyBoth);
    });
    upstream.on("response", (upstreamRes) => {
      // The server refused the upgrade; relay its answer and close.
      this.jar.update(upstreamRes.headers["set-cookie"]);
      const chunks = [];
      upstreamRes.on("data", (chunk) => chunks.push(chunk));
      upstreamRes.on("end", () => {
        const body = Buffer.concat(chunks);
        socket.end(
          `HTTP/1.1 ${upstreamRes.statusCode} ${upstreamRes.statusMessage}\r\n` +
            `Content-Type: ${upstreamRes.headers["content-type"] ?? "text/plain"}\r\n` +
            `Content-Length: ${body.length}\r\nConnection: close\r\n\r\n` +
            body.toString("utf8"),
        );
      });
    });
    upstream.on("error", (cause) => {
      this.log(`websocket upstream error: ${cause.message}`);
      socket.destroy();
    });
    upstream.end();
  }
}

function unavailablePage(targetOrigin) {
  return `<!doctype html><meta charset="utf-8">
<style>body{font:13px -apple-system,system-ui,sans-serif;color:#999;padding:16px}</style>
<p>T3 Code isn't reachable at ${targetOrigin}.</p>
<p>Start the T3 Code app. This page retries every 3 seconds.</p>
<script>setTimeout(() => location.reload(), 3000)</script>`;
}

module.exports = { CookieJar, Relay, LAUNCH_PARAM, SHIM_PATH };
