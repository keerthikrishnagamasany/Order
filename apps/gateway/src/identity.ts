/**
 * Client identification. Scores and rate limits are only as good as the client id behind
 * them: if a client can choose its own id, it can reset its score at will.
 */

import type { IncomingHttpHeaders } from "node:http";

export interface ClientIdentityOptions {
  /**
   * Proxy addresses (your load balancer / CDN egress) whose X-Forwarded-For is trusted.
   * The client is the right-most address in the chain that is NOT one of these. Requests
   * that don't arrive from a trusted proxy have X-Forwarded-For ignored entirely.
   */
  trustedProxies?: readonly string[];
  /**
   * DEMO AND TESTS ONLY. Accept the X-Sim-Client header as the client id so many simulated
   * actors can share one machine. Never enable in production: any client could choose its
   * own id and reset its score at will.
   */
  allowSimulatedClients?: boolean;
}

/** Strip the IPv4-mapped IPv6 prefix Node reports for v4 sockets (`::ffff:1.2.3.4`). */
export function normaliseIp(ip: string): string {
  return ip.startsWith("::ffff:") && ip.includes(".") ? ip.slice(7) : ip;
}

/** Resolve the client id for a request under the given identity policy. */
export function resolveClientId(
  remoteAddress: string | undefined,
  headers: IncomingHttpHeaders,
  policy: ClientIdentityOptions = {},
): string {
  const remote = normaliseIp(remoteAddress ?? "unknown");
  const sim = headers["x-sim-client"];
  if (policy.allowSimulatedClients && typeof sim === "string" && sim) return sim;

  const trusted = new Set((policy.trustedProxies ?? []).map(normaliseIp));
  const xff = headers["x-forwarded-for"];
  if (trusted.has(remote) && xff) {
    const chain = (Array.isArray(xff) ? xff.join(",") : xff)
      .split(",")
      .map((s) => normaliseIp(s.trim()))
      .filter(Boolean);
    for (let i = chain.length - 1; i >= 0; i--) {
      const hop = chain[i] as string;
      if (!trusted.has(hop)) return hop;
    }
  }
  return remote;
}
