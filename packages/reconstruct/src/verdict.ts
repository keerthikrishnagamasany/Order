/**
 * Turn a parsed capture plus ORDER's own decision log into a per-client verdict:
 * what the client was most likely doing, with a confidence label and the evidence,
 * plus block/allow rules proposed for HUMAN approval. Nothing here auto-applies.
 *
 * Intent is inferred from behaviour. Confidence labels are honest: only a canary
 * replay is CERTAIN; everything else is LIKELY or GUESSING.
 */

import type { Confidence } from "@order/core";

export interface DecisionLogEntry {
  ts: string;
  client: string;
  method: string;
  path: string;
  lane: string;
  confidence: string;
  status: number;
  reasons: string[];
}

export interface Hypothesis {
  what: string;
  confidence: Confidence;
  evidence: string;
}

export interface ClientVerdict {
  client: string;
  requests: number;
  lanes: string[];
  detectors: string[];
  hypotheses: Hypothesis[];
  recommendedRules: string[];
}

function has(detectors: Set<string>, pred: (d: string) => boolean): boolean {
  for (const d of detectors) if (pred(d)) return true;
  return false;
}

function classify(paths: string[], lanes: Set<string>, detectors: Set<string>): Hypothesis[] {
  const h: Hypothesis[] = [];
  const sensitive = new Set(paths.filter((p) => ["/.env", "/.git/config", "/admin"].includes(p)));

  if (has(detectors, (d) => d.includes("canary_replayed"))) {
    h.push({
      what: "Scraped a decoy, then replayed a planted token — provably hostile, not a false positive",
      confidence: "CERTAIN",
      evidence: "a canary token that exists only in a decoy response was presented back",
    });
  }
  if (has(detectors, (d) => d.startsWith("sql_injection"))) {
    h.push({ what: "SQL injection attempt", confidence: "LIKELY", evidence: "injection-shaped payload in query/body" });
  }
  if (has(detectors, (d) => d.startsWith("path_traversal"))) {
    h.push({ what: "Path traversal / file-read attempt", confidence: "LIKELY", evidence: "../ sequence or system path in input" });
  }
  if (has(detectors, (d) => d.startsWith("prompt_injection"))) {
    h.push({ what: "Prompt-injection against an agent endpoint", confidence: "LIKELY", evidence: "instruction-override text in body" });
  }
  if (sensitive.size >= 2 || has(detectors, (d) => d.startsWith("scanner_user_agent"))) {
    h.push({ what: "Reconnaissance / vulnerability scanning", confidence: "LIKELY", evidence: `${sensitive.size} sensitive paths probed; scanner UA seen` });
  }
  if (has(detectors, (d) => d.startsWith("authorized_test:"))) {
    const labels = [...detectors].filter((d) => d.startsWith("authorized_test:")).map((d) => d.slice(16));
    h.push({
      what: `Authorized security test (${labels.join(", ")}) — attack payloads expected, allowed and logged`,
      confidence: "CERTAIN",
      evidence: "trusted identity inside an active, in-scope authorized test engagement",
    });
  }
  if (has(detectors, (d) => d.startsWith("authorized_test_expired") || d.startsWith("authorized_test_out_of_scope"))) {
    h.push({
      what: "Tester identity used outside its authorization (expired or out of scope)",
      confidence: "LIKELY",
      evidence: "an authorized-test key was presented after expiry or on a path outside its scope",
    });
  }
  if (has(detectors, (d) => d.startsWith("trusted_key_hard_signal"))) {
    h.push({ what: "Allowlisted key used for an attack payload — likely leaked/abused credential", confidence: "LIKELY", evidence: "trusted key accompanied a HARD attack signal" });
  }
  if (h.length === 0 && lanes.size === 1 && lanes.has("trusted")) {
    h.push({ what: "Legitimate partner agent, normal usage", confidence: "CERTAIN", evidence: "allowlisted key, no signals, benign paths" });
  }
  if (h.length === 0) {
    h.push({ what: "Ordinary user traffic", confidence: "LIKELY", evidence: "no detectors fired, public endpoints only" });
  }
  return h;
}

function recommend(detectors: Set<string>, paths: string[]): string[] {
  const rules: string[] = [];
  if (has(detectors, (d) => d.startsWith("suspicious_path"))) {
    for (const p of [...new Set(paths.filter((p) => ["/.env", "/.git/config"].includes(p)))].sort()) {
      rules.push(`BLOCK path prefix ${p} — no legitimate client requests it`);
    }
  }
  if (has(detectors, (d) => d.startsWith("sql_injection") || d.startsWith("path_traversal"))) {
    rules.push("BLOCK on SQLi/traversal signature after URL-normalisation");
  }
  if (has(detectors, (d) => d.startsWith("scanner_user_agent"))) {
    rules.push("CHALLENGE/decoy any request whose UA matches the scanner fingerprint list");
  }
  if (has(detectors, (d) => d.includes("canary_replayed"))) {
    rules.push("PERMABLOCK + alert any client presenting a canary token");
  }
  if (has(detectors, (d) => d.startsWith("trusted_key_hard_signal"))) {
    rules.push("ROTATE the implicated key and require re-issue — current one likely leaked");
  }
  return rules;
}

/** Build verdicts for every client in a decision log. `skip` drops priming/seed clients. */
export function buildVerdicts(log: DecisionLogEntry[], skip: Set<string> = new Set()): ClientVerdict[] {
  const byClient = new Map<string, { paths: string[]; lanes: Set<string>; detectors: Set<string>; n: number }>();
  for (const e of log) {
    if (skip.has(e.client)) continue;
    let c = byClient.get(e.client);
    if (!c) {
      c = { paths: [], lanes: new Set(), detectors: new Set(), n: 0 };
      byClient.set(e.client, c);
    }
    c.paths.push(e.path);
    c.lanes.add(e.lane);
    c.n += 1;
    for (const r of e.reasons) {
      if (r.includes(":HARD(")) c.detectors.add(`${r.split(":")[0]}:HARD`);
      else if (r.includes(":SUSPECT(")) c.detectors.add(`${r.split(":")[0]}:SUSPECT`);
      else if (r.startsWith("authorized_test")) c.detectors.add(r);
      else if (r.startsWith("canary_replayed") || r.startsWith("trusted_key_hard_signal")) {
        c.detectors.add(r.split("(")[0] as string);
      }
    }
  }
  const verdicts: ClientVerdict[] = [];
  for (const [client, c] of byClient) {
    verdicts.push({
      client,
      requests: c.n,
      lanes: [...c.lanes].sort(),
      detectors: [...c.detectors].sort(),
      hypotheses: classify(c.paths, c.lanes, c.detectors),
      recommendedRules: recommend(c.detectors, c.paths),
    });
  }
  return verdicts;
}
