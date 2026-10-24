/**
 * Reverse-proxy forwarding: how ORDER sits in front of a real application.
 *
 * Only `trusted` and `normal` requests are forwarded. `blocked` is answered at the gateway,
 * and `decoy` is answered with fake data, so neither ever reaches your app.
 *
 * The request body is forwarded as the exact bytes received (never re-encoded), and the
 * upstream response is streamed back rather than buffered. ORDER adds headers your app can
 * use, and strips any copies a client tried to send itself, so they can't be forged:
 *
 *   x-order-lane            trusted | normal
 *   x-order-client          the client id ORDER resolved
 *   x-order-verified-agent  the agent origin, when trusted via Web Bot Auth
 *   x-order-authorized-test the engagement label, when the request ran under an authorized test
 *
 * Your app should only trust x-order-* headers if it accepts traffic from ORDER alone.
 */

import { request as httpRequest, type IncomingMessage, type OutgoingHttpHeaders, type ServerResponse } from "node:http";
import { request as httpsRequest } from "node:https";

export interface UpstreamOptions {
  /** Base URL of the protected app, e.g. "http://127.0.0.1:3000". */
  url: string;
  /** Give up on the upstream after this long. Default 30s. */
  timeoutMs?: number;
  /** Send the client's Host header upstream instead of the upstream's own host. */
  preserveHost?: boolean;
}

export interface ForwardContext {
  lane: string;
  clientId: string;
  verifiedAgent?: string | undefined;
  authorizedTest?: string | undefined;
}

export interface ForwardResult {
  status: number;
  bytes: number;
  error?: string;
}

// Hop-by-hop headers (RFC 9110 §7.6.1) and ones ORDER recomputes.
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

function stripHopByHop(headers: IncomingMessage["headers"]): Record<string, string | string[]> {
  const named = String(headers["connection"] ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  const out: Record<string, string | string[]> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (v === undefined) continue;
    const key = k.toLowerCase();
    if (HOP_BY_HOP.has(key) || named.includes(key)) continue;
    out[key] = v;
  }
  return out;
}

export function forwardToUpstream(
  req: IncomingMessage,
  res: ServerResponse,
  body: Buffer,
  ctx: ForwardContext,
  upstream: UpstreamOptions,
): Promise<ForwardResult> {
  return new Promise((resolve) => {
    const base = new URL(upstream.url);
    const target = new URL(req.url ?? "/", base);
    // Keep the upstream base path as a prefix if one was configured.
    if (base.pathname !== "/") target.pathname = base.pathname.replace(/\/$/, "") + target.pathname;

    const headers = stripHopByHop(req.headers);
    for (const k of Object.keys(headers)) {
      if (k.startsWith("x-order-") || k === "x-sim-client") delete headers[k];
    }
    const prior = req.headers["x-forwarded-for"];
    const remote = req.socket.remoteAddress ?? "";
    headers["x-forwarded-for"] = prior ? `${Array.isArray(prior) ? prior.join(", ") : prior}, ${remote}` : remote;
    headers["x-forwarded-proto"] = "http";
    if (req.headers.host) headers["x-forwarded-host"] = req.headers.host;
    headers["host"] = upstream.preserveHost && req.headers.host ? req.headers.host : base.host;
    headers["x-order-lane"] = ctx.lane;
    headers["x-order-client"] = ctx.clientId;
    if (ctx.verifiedAgent) headers["x-order-verified-agent"] = ctx.verifiedAgent;
    if (ctx.authorizedTest) headers["x-order-authorized-test"] = ctx.authorizedTest;
    if (body.length > 0) headers["content-length"] = String(body.length);
    else delete headers["content-length"];

    const send = base.protocol === "https:" ? httpsRequest : httpRequest;
    let settled = false;
    const finish = (r: ForwardResult) => {
      if (!settled) {
        settled = true;
        resolve(r);
      }
    };
    const fail = (status: number, error: string) => {
      if (!res.headersSent) {
        res.writeHead(status, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: status === 504 ? "upstream timeout" : "bad gateway" }));
      } else {
        res.destroy();
      }
      finish({ status, bytes: 0, error });
    };

    const out = send(
      target,
      { method: req.method ?? "GET", headers: headers as OutgoingHttpHeaders, timeout: upstream.timeoutMs ?? 30_000 },
      (up) => {
        const respHeaders = stripHopByHop(up.headers);
        res.writeHead(up.statusCode ?? 502, respHeaders as OutgoingHttpHeaders);
        let bytes = 0;
        up.on("data", (c: Buffer) => {
          bytes += c.length;
        });
        up.pipe(res);
        up.on("end", () => finish({ status: up.statusCode ?? 502, bytes }));
        up.on("error", (e) => fail(502, e.message));
      },
    );
    out.on("timeout", () => {
      out.destroy();
      fail(504, "upstream timeout");
    });
    out.on("error", (e) => fail(502, e.message));
    if (body.length > 0) out.write(body);
    out.end();
  });
}
