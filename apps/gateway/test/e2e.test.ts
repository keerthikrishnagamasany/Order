import { test } from "node:test";
import assert from "node:assert/strict";
import { createGateway, type DecisionLogLine } from "../src/server.js";
import type { AddressInfo } from "node:net";

async function withGateway(fn: (base: string, log: DecisionLogLine[], canaryProbe: () => string | undefined) => Promise<void>): Promise<void> {
  const log: DecisionLogLine[] = [];
  const allowlist = new Map([["good-key", "partner"]]);
  const gw = createGateway({ allowlist, clientIdentity: { allowSimulatedClients: true }, onDecision: (e) => log.push(e) });
  await new Promise<void>((r) => gw.server.listen(0, r));
  const { port } = gw.server.address() as AddressInfo;
  const base = `http://127.0.0.1:${port}`;
  try {
    await fn(base, log, () => {
      // trigger a decoy and read back a planted canary from the response
      return undefined;
    });
  } finally {
    await new Promise<void>((r) => gw.server.close(() => r()));
  }
}

test("clean request is served normally", async () => {
  await withGateway(async (base, log) => {
    const res = await fetch(`${base}/api/v1/products?category=books`, { headers: { "x-sim-client": "u", "user-agent": "Mozilla/5.0" } });
    assert.equal(res.status, 200);
    assert.equal(log.at(-1)?.lane, "normal");
  });
});

test("hard attack path is blocked with 403", async () => {
  await withGateway(async (base, log) => {
    const res = await fetch(`${base}/.env`, { headers: { "x-sim-client": "a", "user-agent": "sqlmap/1.7" } });
    assert.equal(res.status, 403);
    assert.equal(log.at(-1)?.lane, "blocked");
  });
});

test("encoded SQLi in the query string is blocked", async () => {
  await withGateway(async (base, log) => {
    const res = await fetch(`${base}/api/v1/products?id=1%27%20OR%201%3D1--`, { headers: { "x-sim-client": "a2", "user-agent": "curl/8.0" } });
    assert.equal(res.status, 403);
    assert.equal(log.at(-1)?.lane, "blocked");
  });
});

test("decoy serves a canary that, when replayed, is a CERTAIN block", async () => {
  await withGateway(async (base, log) => {
    // 1. trip the decoy on /admin and scrape the planted token
    const decoyRes = await fetch(`${base}/admin`, { headers: { "x-sim-client": "thief", "user-agent": "sqlmap/1.7" } });
    const decoyBody = (await decoyRes.json()) as { session?: string };
    assert.equal(log.at(-1)?.lane, "decoy");
    assert.ok(decoyBody.session, "decoy should plant a canary token");

    // 2. replay the token -> provably hostile, CERTAIN block
    await fetch(`${base}/api/v1/account?key=${decoyBody.session}`, { headers: { "x-sim-client": "thief2", "user-agent": "curl/8.0" } });
    const last = log.at(-1)!;
    assert.equal(last.lane, "blocked");
    assert.equal(last.confidence, "CERTAIN");
    assert.ok(last.reasons.some((r) => r.startsWith("canary_replayed")));
  });
});

test("Web Bot Auth: a signed agent is trusted, a forged one is decoyed, over real HTTP", async () => {
  const { generateKeyPairSync } = await import("node:crypto");
  const { StaticKeyResolver, signWebBotAuth } = await import("@order/web-bot-auth");
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }) as unknown as import("@order/web-bot-auth").JwkOkp;
  const agentUrl = "https://agent.example";

  const log: DecisionLogLine[] = [];
  const gw = createGateway({
    clientIdentity: { allowSimulatedClients: true },
    botAuth: { resolver: new StaticKeyResolver().add(agentUrl, jwk), authorities: (a: string) => a.startsWith("127.0.0.1:") },
    onDecision: (e) => log.push(e),
  });
  await new Promise<void>((r) => gw.server.listen(0, r));
  const { port } = gw.server.address() as AddressInfo;
  const authority = `127.0.0.1:${port}`;
  try {
    const good = signWebBotAuth({ privateKey, publicJwk: jwk, agentUrl, authority });
    await fetch(`http://${authority}/api/v1/products`, {
      headers: { ...good, "x-sim-client": "signed", "user-agent": "agent/1.0" },
    });
    assert.equal(log.at(-1)?.lane, "trusted");
    assert.ok(log.at(-1)?.reasons.some((r) => r.startsWith("verified_agent:")));

    // Signed for a different host, then replayed here: must not be trusted.
    const replayed = signWebBotAuth({ privateKey, publicJwk: jwk, agentUrl, authority: "other.example" });
    await fetch(`http://${authority}/api/v1/products`, {
      headers: { ...replayed, "x-sim-client": "forger", "user-agent": "agent/1.0" },
    });
    assert.equal(log.at(-1)?.lane, "decoy");
    assert.ok(log.at(-1)?.reasons.some((r) => r.startsWith("bot_auth_invalid")));
  } finally {
    await new Promise<void>((r) => gw.server.close(() => r()));
  }
});

test("client identity: X-Sim-Client is ignored unless explicitly enabled", async () => {
  const { resolveClientId } = await import("../src/server.js");
  assert.equal(resolveClientId("203.0.113.9", { "x-sim-client": "pick-any-id" }), "203.0.113.9");
  assert.equal(resolveClientId("203.0.113.9", { "x-sim-client": "sim" }, { allowSimulatedClients: true }), "sim");
});

test("client identity: X-Forwarded-For is trusted only from a configured proxy", async () => {
  const { resolveClientId } = await import("../src/server.js");
  // Direct client tries to spoof XFF: ignored.
  assert.equal(resolveClientId("198.51.100.7", { "x-forwarded-for": "1.2.3.4" }, { trustedProxies: ["10.0.0.1"] }), "198.51.100.7");
  // Via the trusted proxy: right-most untrusted hop wins, so a forged left-most entry can't.
  assert.equal(
    resolveClientId("10.0.0.1", { "x-forwarded-for": "6.6.6.6, 198.51.100.7" }, { trustedProxies: ["10.0.0.1"] }),
    "198.51.100.7",
  );
  // Multiple trusted hops are skipped.
  assert.equal(
    resolveClientId("::ffff:10.0.0.1", { "x-forwarded-for": "198.51.100.7, 10.0.0.2" }, { trustedProxies: ["10.0.0.1", "10.0.0.2"] }),
    "198.51.100.7",
  );
});

test("client identity: a spoofing scanner can no longer reset its score", async () => {
  const log: DecisionLogLine[] = [];
  const gw = createGateway({ onDecision: (e) => log.push(e) });
  await new Promise<void>((r) => gw.server.listen(0, r));
  const { port } = gw.server.address() as AddressInfo;
  try {
    for (let i = 0; i < 3; i++) {
      await fetch(`http://127.0.0.1:${port}/admin`, { headers: { "x-sim-client": `rotating-${i}`, "user-agent": "sqlmap/1.7" } });
    }
    assert.ok(log.every((l) => l.client === "127.0.0.1"), "all requests attributed to the real socket address");
  } finally {
    await new Promise<void>((r) => gw.server.close(() => r()));
  }
});
