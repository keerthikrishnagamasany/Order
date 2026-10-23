/**
 * @order/gateway — public surface.
 *
 * Ways to run ORDER, all backed by the same `createOrder().check()`:
 *   - Express / Connect middleware:  orderExpress(options)
 *   - Fastify preHandler hook:       orderFastify(options)
 *   - Standalone gateway / proxy:    createGateway(options)
 *   - Your own server:               createOrder(options).check(request)
 */

import type { IncomingMessage } from "node:http";
import type { RawRequest } from "@order/core";
import { resolveClientId, type ClientIdentityOptions } from "./identity.js";

export { createGateway, type Gateway, type GatewayOptions, type DecisionLogLine } from "./server.js";
export { createOrder, type Order, type OrderOptions, type CheckInput, type CheckResult, type DecoyResponder } from "./order.js";
export { orderExpress, orderFastify, type AdapterOptions } from "./middleware.js";
export { forwardToUpstream, type UpstreamOptions, type ForwardContext, type ForwardResult } from "./proxy.js";
export { Metrics, type MetricsInput } from "./metrics.js";
export { resolveClientId, normaliseIp, type ClientIdentityOptions } from "./identity.js";
export { decoyBody, realSampleBody } from "./decoy.js";
export { Engine, CanaryRegistry, MemoryStateStore, RedisStateStore, combine } from "@order/core";
export { referenceRules } from "@order/rules-reference";
export { verifyWebBotAuth, signWebBotAuth, StaticKeyResolver, HttpsDirectoryResolver } from "@order/web-bot-auth";

/**
 * Adapt a Node request + already-read body into the engine's RawRequest, for when you call
 * `Engine.decide()` yourself. The client id follows the same safe policy as the gateway:
 * the socket address, X-Forwarded-For only from `trustedProxies`, never a client-chosen header.
 */
export function toRawRequest(req: IncomingMessage, body: string, identity: ClientIdentityOptions = {}): RawRequest {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
  return {
    method: req.method ?? "GET",
    path: url.pathname,
    query: url.search.replace(/^\?/, ""),
    body,
    userAgent: (req.headers["user-agent"] as string) ?? "",
    identity: (req.headers["x-mcp-key"] as string) ?? undefined,
    clientId: resolveClientId(req.socket.remoteAddress, req.headers, identity),
  };
}
