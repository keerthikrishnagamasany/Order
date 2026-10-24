import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { createGateway, type DecisionLogLine } from "../src/server.js";

interface Seen {
  method: string;
  url: string;
  headers: IncomingMessage["headers"];
  body: Buffer;
}

/** A real upstream app that records everything it receives. */
async function upstreamApp(respond?: (s: Seen) => { status: number; body: string; headers?: Record<string, string> }) {
  const seen: Seen[] = [];
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const s: Seen = { method: req.method ?? "", url: req.url ?? "", headers: req.headers, body: Buffer.concat(chunks) };
    seen.push(s);
    const r = respond?.(s) ?? { status: 200, body: JSON.stringify({ app: "real", path: req.url }) };
    res.writeHead(r.status, { "content-type": "application/json", "x-app": "yes", ...(r.headers ?? {}) });
    res.end(r.body);
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address() as AddressInfo;
  return { seen, url: `http://127.0.0.1:${port}`, close: () => new Promise<void>((r) => server.close(() => r())) };
}

async function gateway(upstreamUrl: string, extra: Parameters<typeof createGateway>[0] = {}) {
  const log: DecisionLogLine[] = [];
  const gw = createGateway({ upstream: { url: upstreamUrl, timeoutMs: 1000 }, onDecision: (e) => log.push(e), ...extra });
  await new Promise<void>((r) => gw.server.listen(0, "127.0.0.1", r));
  const { port } = gw.server.address() as AddressInfo;
  return { log, base: `http://127.0.0.1:${port}`, close: () => new Promise<void>((r) => gw.server.close(() => r())) };
}

test("normal traffic is forwarded and the real app's response comes back", async () => {
  const app = await upstreamApp();
  const gw = await gateway(app.url);
  try {
    const res = await fetch(`${gw.base}/api/v1/products?category=books`, { headers: { "user-agent": "Mozilla/5.0" } });
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-app"), "yes");
    assert.deepEqual(await res.json(), { app: "real", path: "/api/v1/products?category=books" });
    assert.equal(app.seen.length, 1);
    assert.equal(app.seen[0]?.headers["x-order-lane"], "normal");
    assert.equal(app.seen[0]?.headers["x-order-client"], "127.0.0.1");
    assert.ok(String(app.seen[0]?.headers["x-forwarded-for"]).includes("127.0.0.1"));
  } finally {
    await gw.close();
    await app.close();
  }
});

test("blocked traffic never reaches the app", async () => {
  const app = await upstreamApp();
  const gw = await gateway(app.url);
  try {
    const res = await fetch(`${gw.base}/.env`, { headers: { "user-agent": "sqlmap/1.7" } });
    assert.equal(res.status, 403);
    assert.equal(app.seen.length, 0);
  } finally {
    await gw.close();
    await app.close();
  }
});

test("decoyed traffic gets fake data and never reaches the app", async () => {
  const app = await upstreamApp();
  const gw = await gateway(app.url);
  try {
    const res = await fetch(`${gw.base}/admin`, { headers: { "user-agent": "sqlmap/1.7" } });
    const body = (await res.json()) as { session?: string; app?: string };
    assert.equal(gw.log.at(-1)?.lane, "decoy");
    assert.ok(body.session, "decoy content served");
    assert.equal(body.app, undefined);
    assert.equal(app.seen.length, 0);
  } finally {
    await gw.close();
    await app.close();
  }
});

test("POST bodies reach the app byte-for-byte, including binary", async () => {
  const app = await upstreamApp();
  const gw = await gateway(app.url);
  try {
    const payload = Buffer.from([0x00, 0xff, 0x10, 0x80, 0x7f, 0xc3, 0x28]); // not valid UTF-8
    const res = await fetch(`${gw.base}/api/v1/upload`, {
      method: "POST",
      headers: { "content-type": "application/octet-stream", "user-agent": "Mozilla/5.0" },
      body: payload,
    });
    assert.equal(res.status, 200);
    assert.ok(app.seen[0]?.body.equals(payload), "exact bytes forwarded");
  } finally {
    await gw.close();
    await app.close();
  }
});

test("a client can't forge ORDER's headers to the app", async () => {
  const app = await upstreamApp();
  const gw = await gateway(app.url);
  try {
    await fetch(`${gw.base}/api/v1/products`, {
      headers: { "user-agent": "Mozilla/5.0", "x-order-lane": "trusted", "x-order-verified-agent": "https://forged.example" },
    });
    assert.equal(app.seen[0]?.headers["x-order-lane"], "normal");
    assert.equal(app.seen[0]?.headers["x-order-verified-agent"], undefined);
  } finally {
    await gw.close();
    await app.close();
  }
});

test("upstream status codes pass through unchanged", async () => {
  const app = await upstreamApp(() => ({ status: 404, body: '{"error":"no such product"}' }));
  const gw = await gateway(app.url);
  try {
    const res = await fetch(`${gw.base}/api/v1/products/999`, { headers: { "user-agent": "Mozilla/5.0" } });
    assert.equal(res.status, 404);
    assert.deepEqual(await res.json(), { error: "no such product" });
  } finally {
    await gw.close();
    await app.close();
  }
});

test("an unreachable upstream returns 502", async () => {
  const app = await upstreamApp();
  const deadUrl = app.url;
  await app.close();
  const gw = await gateway(deadUrl);
  try {
    const res = await fetch(`${gw.base}/api/v1/products`, { headers: { "user-agent": "Mozilla/5.0" } });
    assert.equal(res.status, 502);
    assert.ok(gw.log.at(-1)?.upstreamError);
  } finally {
    await gw.close();
  }
});

test("oversized bodies are rejected with 413 and never forwarded", async () => {
  const app = await upstreamApp();
  const gw = await gateway(app.url, { maxBodyBytes: 100 });
  try {
    const res = await fetch(`${gw.base}/api/v1/upload`, {
      method: "POST",
      headers: { "user-agent": "Mozilla/5.0" },
      body: "x".repeat(500),
    });
    assert.equal(res.status, 413);
    assert.equal(app.seen.length, 0);
  } finally {
    await gw.close();
    await app.close();
  }
});

test("a custom decoy responder replaces the built-in one", async () => {
  const app = await upstreamApp();
  const gw = await gateway(app.url, { decoy: (path, c) => ({ honeypot: path, token: c.mint("custom", "cst").token }) });
  try {
    const res = await fetch(`${gw.base}/admin`, { headers: { "user-agent": "sqlmap/1.7" } });
    const body = (await res.json()) as { honeypot?: string; token?: string };
    assert.equal(body.honeypot, "/admin");
    assert.match(body.token ?? "", /^cst_/);
  } finally {
    await gw.close();
    await app.close();
  }
});

test("capture is bounded and can be switched off", async () => {
  const { HarRecorder } = await import("@order/core");
  const r = new HarRecorder({ maxEntries: 2 });
  for (let i = 0; i < 5; i++) r.add({ _order: { lane: "normal", confidence: "CERTAIN", reasons: [] } } as never);
  assert.equal(r.count, 2);
  assert.equal(r.dropped, 3);

  const app = await upstreamApp();
  const log: DecisionLogLine[] = [];
  const gw = createGateway({ upstream: { url: app.url }, capture: false, onDecision: (e) => log.push(e) });
  await new Promise<void>((res) => gw.server.listen(0, "127.0.0.1", res));
  const { port } = gw.server.address() as AddressInfo;
  try {
    await fetch(`http://127.0.0.1:${port}/x`, { headers: { "user-agent": "Mozilla/5.0" } });
    assert.equal(gw.recorder.count, 0);
    assert.equal(log.length, 1, "the decision hook still fires");
  } finally {
    await new Promise<void>((res) => gw.server.close(() => res()));
    await app.close();
  }
});

test("an authorized test reaches the app, labelled, and can't be forged by a client", async () => {
  const app = await upstreamApp();
  const gw = await gateway(app.url, {
    allowlist: new Map([["pentest-key", "pen-test firm"]]),
    authorizedTesters: new Map([["pentest-key", { label: "Q4 pen-test", expiresAt: Date.now() + 60_000 }]]),
  });
  try {
    const attack = `${gw.base}/api/v1/products?id=${encodeURIComponent("1' OR 1=1--")}`;
    const res = await fetch(attack, { headers: { "user-agent": "Mozilla/5.0", "x-mcp-key": "pentest-key" } });
    assert.equal(res.status, 200);
    assert.equal(app.seen.length, 1);
    assert.equal(app.seen[0]?.headers["x-order-lane"], "trusted");
    assert.equal(app.seen[0]?.headers["x-order-authorized-test"], "Q4 pen-test");
    assert.equal(gw.log[0]?.authorizedTest, "Q4 pen-test");
    assert.ok(gw.log[0]?.reasons.some((r) => r.startsWith("sql_injection")));

    // an ordinary client claiming to be a test gets nothing
    await fetch(`${gw.base}/api/v1/products`, { headers: { "user-agent": "Mozilla/5.0", "x-order-authorized-test": "Q4 pen-test" } });
    assert.equal(app.seen[1]?.headers["x-order-authorized-test"], undefined);
  } finally {
    await gw.close();
    await app.close();
  }
});
