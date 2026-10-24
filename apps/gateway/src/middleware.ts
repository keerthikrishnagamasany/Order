/**
 * Drop-in adapters for existing apps. Both wrap the same `createOrder().check()`, so they
 * behave exactly like the standalone gateway. Neither imports its framework: they rely on
 * the request/response shapes Express and Fastify already expose, so ORDER adds no
 * dependency to your app.
 *
 * Request bodies: ORDER inspects the body your framework has already parsed. Mount the
 * Express middleware AFTER your body parser (express.json() etc.); in Fastify the hook runs
 * at preHandler, after parsing. If no body has been parsed, only the URL, headers and
 * identity are inspected.
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { createOrder, type CheckResult, type Order, type OrderOptions } from "./order.js";

export interface AdapterOptions extends OrderOptions {
  /** Called once per request with the final status — logging, metrics, capture. */
  onDecision?: (r: CheckResult & { method: string; path: string; status: number }) => void;
}

function bodyText(body: unknown): string {
  if (body === undefined || body === null) return "";
  if (typeof body === "string") return body;
  if (Buffer.isBuffer(body)) return body.toString("utf8");
  try {
    return JSON.stringify(body);
  } catch {
    return "";
  }
}

function pathOf(url: string): string {
  const q = url.indexOf("?");
  return q >= 0 ? url.slice(0, q) : url;
}

/** Make an Order from options, or reuse one you built yourself. */
function orderFrom(o: AdapterOptions | Order): Order {
  return "check" in o ? o : createOrder(o);
}

// ---------------------------------------------------------------- Express / Connect

type Next = (err?: unknown) => void;
type ExpressRequest = IncomingMessage & { body?: unknown; originalUrl?: string };
type ExpressResponse = ServerResponse & { locals?: Record<string, unknown> };

/**
 * Express / Connect middleware.
 *
 *   app.use(express.json());
 *   app.use(orderExpress({ botAuth: { resolver: new HttpsDirectoryResolver(), authorities: ["api.example.com"] } }));
 *   app.get("/api/items", (req, res) => res.json({ lane: res.locals.order.decision.lane }));
 *
 * Blocked and decoyed requests are answered here and never reach your routes. For the rest,
 * the verdict is on `res.locals.order` (and `req.order`).
 */
export function orderExpress(options: AdapterOptions | Order = {}) {
  const order = orderFrom(options);
  const onDecision = "check" in options ? undefined : options.onDecision;
  return (req: ExpressRequest, res: ExpressResponse, next: Next): void => {
    const url = req.originalUrl ?? req.url ?? "/";
    order
      .check({ method: req.method ?? "GET", url, headers: req.headers, body: bodyText(req.body), remoteAddress: req.socket.remoteAddress })
      .then((r) => {
        if (onDecision) res.once("finish", () => onDecision({ ...r, method: req.method ?? "GET", path: pathOf(url), status: res.statusCode }));
        if (r.respond) {
          res.statusCode = r.respond.status;
          res.setHeader("content-type", r.respond.contentType);
          res.end(r.respond.body);
          return;
        }
        if (res.locals) res.locals["order"] = r;
        (req as ExpressRequest & { order?: CheckResult }).order = r;
        next();
      })
      .catch(next);
  };
}

// ---------------------------------------------------------------- Fastify

interface FastifyRequestLike {
  method: string;
  url: string;
  headers: IncomingMessage["headers"];
  body?: unknown;
  raw: IncomingMessage;
}
interface FastifyReplyLike {
  code(status: number): FastifyReplyLike;
  header(name: string, value: string): FastifyReplyLike;
  send(payload?: unknown): unknown;
  raw: ServerResponse;
}

/**
 * Fastify preHandler hook.
 *
 *   fastify.addHook("preHandler", orderFastify({ ... }));
 *
 * Blocked and decoyed requests are answered by the hook. For the rest, the verdict is on
 * `request.order`.
 */
export function orderFastify(options: AdapterOptions | Order = {}) {
  const order = orderFrom(options);
  const onDecision = "check" in options ? undefined : options.onDecision;
  return async (request: FastifyRequestLike, reply: FastifyReplyLike): Promise<void> => {
    const r = await order.check({
      method: request.method,
      url: request.url,
      headers: request.headers,
      body: bodyText(request.body),
      remoteAddress: request.raw.socket.remoteAddress,
    });
    if (onDecision) {
      reply.raw.once("finish", () => onDecision({ ...r, method: request.method, path: pathOf(request.url), status: reply.raw.statusCode }));
    }
    if (r.respond) {
      await reply.code(r.respond.status).header("content-type", r.respond.contentType).send(r.respond.body);
      return;
    }
    (request as FastifyRequestLike & { order?: CheckResult }).order = r;
  };
}
