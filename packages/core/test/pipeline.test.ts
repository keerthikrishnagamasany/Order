import { test } from "node:test";
import assert from "node:assert/strict";
import { Engine } from "../src/pipeline.js";
import { CanaryRegistry } from "../src/canary.js";
import type { RulePack, Signal } from "../src/types.js";

/** A tiny rule pack so core is tested in isolation from the reference rules. */
const rules: RulePack = {
  id: "test",
  inspect(f): Signal[] {
    const out: Signal[] = [];
    if (f.path === "/.env") out.push({ name: "suspicious_path", severity: "HARD", where: "path", excerpt: f.path });
    if (/' or 1=1/i.test(f.query)) out.push({ name: "sql_injection", severity: "HARD", where: "query", excerpt: "' or 1=1" });
    if (/<script/i.test(f.body)) out.push({ name: "xss", severity: "SUSPECT", where: "body", excerpt: "<script" });
    if (/sqlmap/i.test(f.userAgent)) out.push({ name: "scanner_user_agent", severity: "SUSPECT", where: "header", excerpt: "sqlmap" });
    return out;
  },
};

function engine(): { e: Engine; canaries: CanaryRegistry } {
  const canaries = new CanaryRegistry();
  const allowlist = new Map([["good-key", "partner"]]);
  return { e: new Engine({ rules, allowlist, canaries, now: () => 1000 }), canaries };
}

test("clean request -> normal", () => {
  const { e } = engine();
  const d = e.decide({ method: "GET", path: "/api/products", clientId: "u1" });
  assert.equal(d.lane, "normal");
  assert.equal(d.confidence, "CERTAIN");
});

test("allowlisted key -> trusted", () => {
  const { e } = engine();
  const d = e.decide({ method: "GET", path: "/api/orders", identity: "good-key", clientId: "p1" });
  assert.equal(d.lane, "trusted");
});

test("HARD path -> blocked", () => {
  const { e } = engine();
  const d = e.decide({ method: "GET", path: "/.env", clientId: "a1" });
  assert.equal(d.lane, "blocked");
  assert.equal(d.confidence, "LIKELY");
});

test("encoded SQLi is caught after normalisation", () => {
  const { e } = engine();
  // %27+OR+1%3D1 decodes to ' OR 1=1
  const d = e.decide({ method: "GET", path: "/api/products", query: "id=1%27+OR+1%3D1", clientId: "a2" });
  assert.equal(d.lane, "blocked");
});

test("SUSPECT body -> decoy", () => {
  const { e } = engine();
  const d = e.decide({ method: "POST", path: "/api/search", body: "<script>x</script>", clientId: "a3" });
  assert.equal(d.lane, "decoy");
  assert.equal(d.confidence, "GUESSING");
});

test("trusted key carrying a HARD signal -> blocked (leaked key)", () => {
  const { e } = engine();
  const d = e.decide({ method: "GET", path: "/api/x", query: "id=1' or 1=1", identity: "good-key", clientId: "p2" });
  assert.equal(d.lane, "blocked");
  assert.ok(d.reasons.some((r) => r.startsWith("trusted_key_hard_signal")));
});

test("verified agent -> trusted", () => {
  const { e } = engine();
  const d = e.decide({ method: "GET", path: "/api/x", clientId: "bot", verifiedAgent: "https://agent.example" });
  assert.equal(d.lane, "trusted");
  assert.ok(d.reasons.some((r) => r.startsWith("verified_agent:")));
});

test("verified agent carrying a HARD signal -> blocked", () => {
  const { e } = engine();
  const d = e.decide({ method: "GET", path: "/.env", clientId: "bot2", verifiedAgent: "https://agent.example" });
  assert.equal(d.lane, "blocked");
});

test("extra SUSPECT signal (forged signature) -> decoy", () => {
  const { e } = engine();
  const d = e.decide({
    method: "GET",
    path: "/api/x",
    clientId: "forger",
    extraSignals: [{ name: "bot_auth_invalid", severity: "SUSPECT", where: "identity", excerpt: "bad sig" }],
  });
  assert.equal(d.lane, "decoy");
});

test("canary replay -> blocked, CERTAIN", () => {
  const { e, canaries } = engine();
  const c = canaries.mint("decoy /admin token", "adm");
  const d = e.decide({ method: "GET", path: "/api/account", query: `key=${c.token}`, clientId: "thief" });
  assert.equal(d.lane, "blocked");
  assert.equal(d.confidence, "CERTAIN");
  assert.ok(d.reasons.some((r) => r.startsWith("canary_replayed")));
});
