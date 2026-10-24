import { test } from "node:test";
import assert from "node:assert/strict";
import type { RulePack } from "@order/core";
import { compileRules, fromHar, synthesizeRules, uaToken, type CapturedRequest } from "../src/synthesize.js";

let n = 0;
function req(p: Partial<CapturedRequest>): CapturedRequest {
  return {
    ordinal: n++,
    ts: "2026-10-24T00:00:00Z",
    client: "c",
    method: "GET",
    path: "/",
    userAgent: "Mozilla/5.0",
    status: 200,
    lane: "normal",
    confidence: "CERTAIN",
    reasons: [],
    ...p,
  };
}

const capture: CapturedRequest[] = [
  // legitimate traffic
  req({ client: "user", path: "/api/v1/products" }),
  req({ client: "partner", path: "/api/v1/orders", userAgent: "swift-agent/1.0", lane: "trusted" }),
  // a scanner probing a path no rule knows about
  req({ client: "scan-1", path: "/wp-json/wp/v2/users", userAgent: "zgrab/0.x", lane: "decoy", reasons: ["score=3"] }),
  req({ client: "scan-2", path: "/wp-json/wp/v2/users", userAgent: "zgrab/0.x", lane: "decoy", reasons: ["score=3"] }),
  // blocked for its PAYLOAD on a normal path — the path must not be blamed
  req({
    client: "probe",
    path: "/api/v1/products",
    userAgent: "curl/8.0",
    lane: "blocked",
    reasons: ["sql_injection:HARD(query='1' OR 1=1')"],
  }),
  // a leaked partner key: hostile request with the partner's own user-agent
  req({
    client: "leaked",
    path: "/api/v1/orders",
    userAgent: "swift-agent/1.0",
    lane: "blocked",
    reasons: ["sql_injection:HARD(query='UNION SELECT')", "trusted_key_hard_signal:partner"],
  }),
];

function find(id: string) {
  const p = synthesizeRules(capture).find((x) => x.id === id);
  assert.ok(p, `expected proposal ${id}`);
  return p;
}

test("uaToken extracts the product token", () => {
  assert.equal(uaToken("sqlmap/1.7"), "sqlmap");
  assert.equal(uaToken("Mozilla/5.0 (Macintosh)"), "mozilla");
  assert.equal(uaToken("no-slash"), null);
});

test("a path probed only by hostile clients becomes a LIKELY proposal with evidence", () => {
  const p = find("path:/wp-json/wp/v2/users");
  assert.equal(p.status, "proposed");
  assert.equal(p.confidence, "LIKELY");
  assert.equal(p.support.clients, 2);
  assert.equal(p.support.ordinals.length, 2);
  assert.equal(p.approved, false, "never auto-approved");
});

test("a path blocked only for its payload is not blamed", () => {
  const all = synthesizeRules(capture);
  assert.equal(all.find((x) => x.id === "path:/api/v1/products"), undefined);
});

test("a rule that would hit trusted traffic is rejected (leaked-key UA)", () => {
  const p = find("user_agent:swift-agent");
  assert.equal(p.status, "rejected");
  assert.equal(p.falsePositives.hits, 1);
  assert.match(p.reason, /trusted/);
});

test("single-client evidence is only GUESSING", () => {
  const p = find("user_agent:curl");
  assert.equal(p.confidence, "GUESSING");
  assert.equal(p.severity, "SUSPECT");
});

test("generic browser tokens are never proposed", () => {
  assert.equal(synthesizeRules(capture).some((x) => x.match === "mozilla"), false);
});

test("proposals already covered by the existing pack are flagged redundant", () => {
  const existing: RulePack = {
    id: "x",
    inspect: (f) => (/zgrab/.test(f.userAgent) ? [{ name: "s", severity: "SUSPECT", where: "header", excerpt: "zgrab" }] : []),
  };
  const p = synthesizeRules(capture, { existing }).find((x) => x.id === "user_agent:zgrab");
  assert.equal(p?.redundant, true);
});

test("compileRules only activates approved, non-rejected proposals", () => {
  const proposals = synthesizeRules(capture).map((p) => ({ ...p, approved: true }));
  const pack = compileRules(proposals);
  const facts = { method: "GET", query: "", body: "", clientId: "z" };
  assert.ok(pack.inspect({ ...facts, path: "/wp-json/wp/v2/users", userAgent: "x/1" }).some((s) => s.name === "learned_path"));
  // rejected even though approved: must not fire on the partner's UA
  assert.equal(pack.inspect({ ...facts, path: "/api/v1/orders", userAgent: "swift-agent/1.0" }).length, 0);
});

test("unapproved proposals compile to an empty pack", () => {
  const pack = compileRules(synthesizeRules(capture));
  assert.equal(pack.inspect({ method: "GET", path: "/wp-json/wp/v2/users", query: "", body: "", userAgent: "zgrab/1", clientId: "z" }).length, 0);
});

test("authorized-test traffic can neither propose nor veto a rule", () => {
  const withTester: CapturedRequest[] = [
    ...capture,
    // a hired tester hitting the scanner path while trusted would otherwise veto the rule
    req({ client: "pentest", path: "/wp-json/wp/v2/users", lane: "trusted", authorizedTest: "Q4 pen-test" }),
    // and its own probes on new paths must not become rules either
    req({ client: "pentest", path: "/only-the-tester-hit-this", lane: "trusted", reasons: ["authorized_test:Q4 pen-test"] }),
  ];
  const ps = synthesizeRules(withTester);
  const wp = ps.find((p) => p.id === "path:/wp-json/wp/v2/users");
  assert.equal(wp?.status, "proposed");
  assert.equal(wp?.falsePositives.hits, 0);
  assert.equal(ps.some((p) => p.match === "/only-the-tester-hit-this"), false);
});

test("fromHar reads the authorized-test label from _order or from reasons", () => {
  const har = {
    log: {
      entries: [
        { request: { url: "http://x/a", headers: [] }, _order: { lane: "trusted", authorizedTest: "T1" } },
        { request: { url: "http://x/b", headers: [] }, _order: { lane: "trusted", reasons: ["authorized_test:T2"] } },
        { request: { url: "http://x/c", headers: [] }, _order: { lane: "trusted" } },
      ],
    },
  };
  assert.deepEqual(fromHar(har).map((r) => r.authorizedTest), ["T1", "T2", undefined]);
});
