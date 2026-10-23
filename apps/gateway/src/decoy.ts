/**
 * Decoy data provider. When a request is routed to the `decoy` lane, ORDER serves
 * convincing but fake data seeded with canary tokens, so a hostile client reveals
 * intent without ever touching real data. The canaries planted here are what later
 * make a replay provably hostile.
 */

import type { CanaryRegistry } from "@order/core";

export function decoyBody(path: string, canaries: CanaryRegistry): unknown {
  const p = path.toLowerCase();
  if (p.startsWith("/.env") || p.includes("config")) {
    return {
      _file: ".env",
      API_KEY: canaries.mint("decoy /.env key", "sk_live").token,
      DB_HOST: "10.0.0.5",
      DEBUG: "true",
    };
  }
  if (p.startsWith("/admin")) {
    return {
      session: canaries.mint("decoy /admin token", "adm_sess").token,
      role: "admin",
      users: 1284,
      panel: "/admin/v2",
    };
  }
  if (p.includes("user")) {
    return {
      users: Array.from({ length: 5 }, (_, i) => ({ id: i + 1, email: `user${i + 1}@example.invalid` })),
    };
  }
  return { status: "ok", data: [], note: "no records" };
}

/** Stand-in for the genuine platform response served to trusted/normal clients. */
export function realSampleBody(path: string): unknown {
  return { status: "ok", path, data: { items: 3, tier: "public" } };
}
