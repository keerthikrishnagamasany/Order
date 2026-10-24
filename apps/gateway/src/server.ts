/**
 * Standalone gateway, built on Node's stdlib `http` (zero runtime dependencies).
 *
 * Two modes:
 *   - sample mode (no `upstream`): answers with sample data, for demos and tests;
 *   - proxy mode (`upstream` set): forwards trusted/normal traffic to your real app, while
 *     blocked and decoy requests are answered here and never reach it.
 *
 * The decision itself comes from `createOrder().check()` — the same core the Express and
 * Fastify adapters use — so every way of running ORDER behaves identically.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { HarRecorder, type CanaryRegistry, type Engine, type HarRecorderOptions } from "@order/core";
import { realSampleBody } from "./decoy.js";
import { normaliseIp } from "./identity.js";
import type { Metrics } from "./metrics.js";
import { createOrder, type OrderOptions } from "./order.js";
import { forwardToUpstream, type UpstreamOptions } from "./proxy.js";

export { resolveClientId, type ClientIdentityOptions } from "./identity.js";
export type { DecoyResponder } from "./order.js";

export interface GatewayOptions extends OrderOptions {
  /** Forward trusted/normal traffic to this app. Without it, sample data is served. */
  upstream?: UpstreamOptions;
  /** Capture settings, or `false` to record nothing. */
  capture?: HarRecorderOptions | false;
  /** Largest request body accepted, in bytes. Larger requests get 413. Default 1 MiB. */
  maxBodyBytes?: number;
  /**
   * Serve Prometheus metrics. By default only to loopback clients that are not configured
   * trusted proxies, so they aren't exposed to the internet through a local reverse proxy;
   * pass `allow` to change who may read them.
   */
  metrics?: { registry: Metrics; path?: string; allow?: (remoteAddress: string) => boolean };
  /** Called after every request — plug in your own logger here. */
  onDecision?: (entry: DecisionLogLine) => void;
}

export interface DecisionLogLine {
  ts: string;
  client: string;
  method: string;
  path: string;
  lane: string;
  confidence: string;
  status: number;
  reasons: string[];
  /** Milliseconds ORDER spent verifying and deciding (excludes upstream time). */
  decideMs: number;
  /** Web Bot Auth outcome, when the request carried a signature. */
  botAuth?: string;
  /** Engagement label, when the request ran under an authorized security test. */
  authorizedTest?: string;
  /** Set when the request was forwarded and the upstream failed. */
  upstreamError?: string;
}

export interface Gateway {
  server: Server;
  recorder: HarRecorder;
  canaries: CanaryRegistry;
  engine: Engine;
}

/** Read the body up to `cap` bytes. Reports overflow instead of silently truncating. */
async function readBody(req: IncomingMessage, cap: number): Promise<{ buf: Buffer; overflow: boolean }> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > cap) return { buf: Buffer.alloc(0), overflow: true };
    chunks.push(chunk as Buffer);
  }
  return { buf: Buffer.concat(chunks), overflow: false };
}

const isLoopback = (ip: string) => {
  const a = normaliseIp(ip);
  return a === "::1" || a.startsWith("127.");
};

export function createGateway(opts: GatewayOptions = {}): Gateway {
  const order = createOrder(opts);
  const recorder = new HarRecorder(opts.capture === false ? {} : (opts.capture ?? {}));
  const maxBody = opts.maxBodyBytes ?? 1024 * 1024;
  const metricsPath = opts.metrics?.path ?? "/__order/metrics";
  // A request from a trusted proxy is really from whoever the proxy relays: never "local".
  const trustedPeers = new Set((opts.clientIdentity?.trustedProxies ?? []).map(normaliseIp));
  const defaultMetricsAllow = (peer: string) => isLoopback(peer) && !trustedPeers.has(normaliseIp(peer));

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    handle(req, res).catch(() => {
      if (!res.headersSent) {
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "internal error" }));
      }
    });
  });

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const startedISO = new Date().toISOString();
    const t0 = process.hrtime.bigint();
    const rawUrl = req.url ?? "/";
    const url = new URL(rawUrl, `http://${req.headers.host ?? "localhost"}`);

    if (opts.metrics && req.method === "GET" && url.pathname === metricsPath) {
      const allow = opts.metrics.allow ?? defaultMetricsAllow;
      if (allow(req.socket.remoteAddress ?? "")) {
        res.writeHead(200, { "content-type": "text/plain; version=0.0.4" });
        res.end(opts.metrics.registry.render());
        return;
      }
      // Not allowed: fall through and treat it like any other request.
    }

    let bodyBuf = Buffer.alloc(0);
    if (req.method !== "GET" && req.method !== "HEAD") {
      const read = await readBody(req, maxBody);
      if (read.overflow) {
        res.writeHead(413, { "content-type": "application/json", connection: "close" });
        res.end(JSON.stringify({ error: "request body too large" }));
        return;
      }
      bodyBuf = read.buf;
    }
    // ORDER inspects the bytes it receives. A compressed body would be inspected as noise and
    // then decompressed by the app, so non-identity content codings are refused, not forwarded.
    const coding = String(req.headers["content-encoding"] ?? "").trim().toLowerCase();
    if (bodyBuf.length > 0 && coding !== "" && coding !== "identity") {
      res.writeHead(415, { "content-type": "application/json", connection: "close" });
      res.end(JSON.stringify({ error: "unsupported content-encoding" }));
      return;
    }
    const body = bodyBuf.toString("utf8");

    const r = await order.check({ method: req.method ?? "GET", url: rawUrl, headers: req.headers, body, remoteAddress: req.socket.remoteAddress });
    const { decision, clientId } = r;

    let status = decision.status;
    let respText: string;
    let upstreamError: string | undefined;

    if (r.respond) {
      respText = r.respond.body;
      res.writeHead(r.respond.status, { "content-type": r.respond.contentType });
      res.end(respText);
    } else if (opts.upstream) {
      const f = await forwardToUpstream(req, res, bodyBuf, { lane: decision.lane, clientId, verifiedAgent: r.verifiedAgent, authorizedTest: decision.authorizedTest }, opts.upstream);
      status = f.status;
      upstreamError = f.error;
      respText = `[proxied to upstream: ${f.bytes} bytes]`; // real app responses are not retained
    } else {
      respText = JSON.stringify(realSampleBody(url.pathname));
      res.writeHead(status, { "content-type": "application/json" });
      res.end(respText);
    }

    if (opts.capture !== false) {
      const waitedMs = Number(process.hrtime.bigint() - t0) / 1e6;
      recorder.record({
          startedISO,
          waitedMs: Math.round(waitedMs * 1000) / 1000,
          method: req.method ?? "GET",
          url: url.toString(),
          reqHeaders: Object.fromEntries(Object.entries(req.headers).map(([k, v]) => [k, Array.isArray(v) ? v.join(",") : (v ?? "")])),
          reqBody: body,
          status,
          respBody: respText,
          decision,
          clientId,
      });
    }

    const line: DecisionLogLine = {
      ts: startedISO,
      client: clientId,
      method: req.method ?? "GET",
      path: url.pathname,
      lane: decision.lane,
      confidence: decision.confidence,
      status,
      reasons: [...decision.reasons],
      decideMs: r.decideMs,
      ...(r.botAuth ? { botAuth: r.botAuth } : {}),
      ...(decision.authorizedTest ? { authorizedTest: decision.authorizedTest } : {}),
      ...(upstreamError ? { upstreamError } : {}),
    };
    opts.metrics?.registry.observe(line);
    opts.onDecision?.(line);
  }

  return { server, recorder, canaries: order.canaries, engine: order.engine };
}
