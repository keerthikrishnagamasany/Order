import { test } from "node:test";
import assert from "node:assert/strict";
import { buildVerdicts, type DecisionLogEntry } from "../src/verdict.js";

const e = (client: string, lane: string, reasons: string[]): DecisionLogEntry => ({
  ts: "2026-10-24T00:00:00Z", client, method: "GET", path: "/api/items", lane, confidence: "CERTAIN", status: 200, reasons,
});

test("an authorized test is reported as such, not as a leaked key", () => {
  const [v] = buildVerdicts([e("pentest", "trusted", ["sql_injection:HARD(query='or 1=1')", "authorized_test:Q4 pen-test"])]);
  assert.ok(v?.hypotheses.some((h) => h.what.startsWith("Authorized security test (Q4 pen-test)")));
  assert.equal(v?.hypotheses.some((h) => h.what.includes("leaked")), false);
  assert.equal(v?.recommendedRules.some((r) => r.startsWith("ROTATE")), false);
});

test("a tester key used after expiry is flagged", () => {
  const [v] = buildVerdicts([
    e("pentest", "blocked", ["sql_injection:HARD(query='or 1=1')", "authorized_test_expired:Q4 pen-test", "trusted_key_hard_signal:pen-test firm"]),
  ]);
  assert.ok(v?.hypotheses.some((h) => h.what.startsWith("Tester identity used outside its authorization")));
});
