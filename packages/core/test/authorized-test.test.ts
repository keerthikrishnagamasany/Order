import { test } from "node:test";
import assert from "node:assert/strict";
import { Engine } from "../src/pipeline.js";
import { CanaryRegistry } from "../src/canary.js";
import type { AuthorizedTester, RulePack, Signal } from "../src/types.js";

const rules: RulePack = {
  id: "test",
  inspect(f): Signal[] {
    const out: Signal[] = [];
    if (f.path === "/.env") out.push({ name: "suspicious_path", severity: "HARD", where: "path", excerpt: f.path });
    if (/' or 1=1/i.test(f.query)) out.push({ name: "sql_injection", severity: "HARD", where: "query", excerpt: "' or 1=1" });
    return out;
  },
};

const NOW = 1_000_000;
function engine(testers: Record<string, AuthorizedTester>, now = NOW) {
  const canaries = new CanaryRegistry();
  const allowlist = new Map([
    ["pentest-key", "external pen-test firm"],
    ["partner-key", "partner"],
  ]);
  const e = new Engine({ rules, allowlist, canaries, authorizedTesters: new Map(Object.entries(testers)), now: () => now });
  return { e, canaries };
}

const SQLI = { method: "GET", path: "/api/items", query: "id=1' OR 1=1", clientId: "t1" };

test("authorized tester: attack payload is allowed, labelled and logged, not blocked", () => {
  const { e } = engine({ "pentest-key": { label: "Q4 pen-test", expiresAt: NOW + 60_000 } });
  const d = e.decide({ ...SQLI, identity: "pentest-key" });
  assert.equal(d.lane, "trusted");
  assert.equal(d.authorizedTest, "Q4 pen-test");
  assert.ok(d.reasons.includes("authorized_test:Q4 pen-test"));
  // the evidence is kept, so the test's findings are still visible
  assert.ok(d.signals.some((s) => s.name === "sql_injection"));
});

test("without a tester entry, the same trusted key is still treated as leaked", () => {
  const { e } = engine({ "pentest-key": { label: "Q4 pen-test", expiresAt: NOW + 60_000 } });
  const d = e.decide({ ...SQLI, identity: "partner-key" });
  assert.equal(d.lane, "blocked");
  assert.equal(d.authorizedTest, undefined);
});

test("expired authorization falls back to leaked-key handling, with a reason", () => {
  const { e } = engine({ "pentest-key": { label: "Q4 pen-test", expiresAt: NOW } });
  const d = e.decide({ ...SQLI, identity: "pentest-key" });
  assert.equal(d.lane, "blocked");
  assert.ok(d.reasons.includes("authorized_test_expired:Q4 pen-test"));
});

test("out-of-scope path falls back to leaked-key handling", () => {
  const { e } = engine({ "pentest-key": { label: "API only", expiresAt: NOW + 60_000, paths: ["/api"] } });
  const inScope = e.decide({ ...SQLI, identity: "pentest-key" });
  assert.equal(inScope.lane, "trusted");
  const out = e.decide({ method: "GET", path: "/.env", identity: "pentest-key", clientId: "t1" });
  assert.equal(out.lane, "blocked");
  assert.ok(out.reasons.includes("authorized_test_out_of_scope:API only"));
  // prefix matching is by path segment: /apiary is not inside /api
  const sibling = e.decide({ method: "GET", path: "/apiary", query: "id=1' OR 1=1", identity: "pentest-key", clientId: "t1" });
  assert.equal(sibling.lane, "blocked");
});

test("a tester entry alone grants nothing: the identity must also be trusted", () => {
  const { e } = engine({ "unknown-key": { label: "rogue", expiresAt: NOW + 60_000 } });
  const d = e.decide({ ...SQLI, identity: "unknown-key" });
  assert.equal(d.lane, "blocked");
  assert.equal(d.authorizedTest, undefined);
});

test("verified agents can be authorized testers via agent:<origin>", () => {
  const { e } = engine({ "agent:https://scanner.example": { label: "own scanner", expiresAt: NOW + 60_000 } });
  const d = e.decide({ ...SQLI, verifiedAgent: "https://scanner.example" });
  assert.equal(d.lane, "trusted");
  assert.equal(d.authorizedTest, "own scanner");
});

test("a canary replay still blocks an authorized tester", () => {
  const { e, canaries } = engine({ "pentest-key": { label: "Q4 pen-test", expiresAt: NOW + 60_000 } });
  const token = canaries.mint("decoy /.env key").token;
  const d = e.decide({ method: "POST", path: "/api/login", body: `key=${token}`, identity: "pentest-key", clientId: "t1" });
  assert.equal(d.lane, "blocked");
  assert.equal(d.confidence, "CERTAIN");
});

test("an authorization without a finite expiry is rejected at construction", () => {
  assert.throws(() => engine({ "pentest-key": { label: "forever", expiresAt: Infinity } }), /finite expiresAt/);
});
