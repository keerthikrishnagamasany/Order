/**
 * `pnpm eval` — do learned rules hold up on traffic they were not learned from?
 *
 *   1. Learn: run rule synthesis on the frozen baseline capture (benchmarks/baseline.har,
 *      the 15 requests from `pnpm demo`).
 *   2. Approve: stand in for the human reviewer with one fixed, printed policy — approve
 *      every proposal that was not rejected and is not already covered by the built-in rules.
 *   3. Enforce: start a real upstream app behind a real ORDER gateway, once with the built-in
 *      rules only and once with the learned rules added, and send the held-out set
 *      (benchmarks/holdout.json) through each.
 *   4. Score: a malicious request counts as caught if it never reaches the app (decoy or
 *      blocked). A benign request counts as a false positive if it does not reach the app.
 *
 * Results are written to benchmarks/RESULTS.md. Small, hand-labelled sets like this one
 * show behaviour and failure cases; they are not a statistical accuracy claim.
 */

import { readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { generateKeyPairSync } from "node:crypto";
import { combine, type RulePack } from "../packages/core/src/index.js";
import { referenceRules } from "../packages/rules-reference/src/index.js";
import { StaticKeyResolver, signWebBotAuth, type JwkOkp } from "../packages/web-bot-auth/src/index.js";
import { compileRules, fromHar, synthesizeRules } from "../packages/reconstruct/src/index.js";
import { createGateway, type DecisionLogLine } from "../apps/gateway/src/server.js";

interface Labelled {
  id: string;
  label: "benign" | "malicious";
  note: string;
  client: string;
  method: string;
  path: string;
  query?: string;
  body?: string;
  ua: string;
  key?: string;
  signed?: boolean;
}

interface Outcome {
  lane: string;
  reachedApp: boolean;
  learnedFired: boolean;
}

const here = new URL(".", import.meta.url);
const holdout = (JSON.parse(readFileSync(new URL("holdout.json", here), "utf8")) as { requests: Labelled[] }).requests;
const baseline = JSON.parse(readFileSync(new URL("baseline.har", here), "utf8")) as unknown;

// ---- 1 + 2: learn and approve -------------------------------------------------------------
const proposals = synthesizeRules(fromHar(baseline), { existing: referenceRules });
const approved = proposals.map((p) => ({ ...p, approved: p.status === "proposed" && !p.redundant }));
const learned = compileRules(approved);
const approvedList = approved.filter((p) => p.approved);

// ---- 3: enforce through a running gateway -------------------------------------------------
const AGENT_URL = "https://agent.example";
const agentKeys = generateKeyPairSync("ed25519");
const agentJwk = agentKeys.publicKey.export({ format: "jwk" }) as unknown as JwkOkp;
const resolver = new StaticKeyResolver().add(AGENT_URL, agentJwk);

async function run(rules: RulePack): Promise<Map<string, Outcome>> {
  const reached = new Set<string>();
  const app = createServer((req, res) => {
    const id = req.headers["x-eval-id"];
    if (typeof id === "string") reached.add(id);
    req.resume();
    res.writeHead(200, { "content-type": "application/json" });
    res.end('{"app":"real"}');
  });
  await new Promise<void>((r) => app.listen(0, "127.0.0.1", r));
  const appUrl = `http://127.0.0.1:${(app.address() as AddressInfo).port}`;

  const log: DecisionLogLine[] = [];
  const { server } = createGateway({
    rules,
    upstream: { url: appUrl, timeoutMs: 2000 },
    allowlist: new Map([["mcp_live_partner_swift_7f3a", "partner-swift"]]),
    botAuth: { resolver },
    // Evaluation only: lets the labelled actors share one machine. Never in production.
    clientIdentity: { allowSimulatedClients: true },
    capture: false,
    onDecision: (e) => log.push(e),
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as AddressInfo).port;

  const out = new Map<string, Outcome>();
  for (const r of holdout) {
    const headers: Record<string, string> = { "x-sim-client": r.client, "user-agent": r.ua, "x-eval-id": r.id };
    if (r.key) headers["x-mcp-key"] = r.key;
    if (r.body) headers["content-type"] = "application/json";
    if (r.signed) {
      Object.assign(headers, signWebBotAuth({ privateKey: agentKeys.privateKey, publicJwk: agentJwk, agentUrl: AGENT_URL, authority: `127.0.0.1:${port}` }));
    }
    const q = r.query ? `?${encodeURIComponent(r.query).replace(/%3D/g, "=").replace(/%26/g, "&")}` : "";
    const before = log.length;
    await fetch(`http://127.0.0.1:${port}${r.path}${q}`, { method: r.method, headers, ...(r.body ? { body: r.body } : {}) });
    const d = log[before];
    out.set(r.id, {
      lane: d?.lane ?? "?",
      reachedApp: reached.has(r.id),
      learnedFired: d?.reasons.some((x) => x.startsWith("learned_")) ?? false,
    });
  }
  await new Promise<void>((r) => server.close(() => r()));
  await new Promise<void>((r) => app.close(() => r()));
  return out;
}

const base = await run(referenceRules);
const withLearned = await run(combine(referenceRules, learned));

// ---- 4: score -----------------------------------------------------------------------------
function score(o: Map<string, Outcome>) {
  const mal = holdout.filter((r) => r.label === "malicious");
  const ben = holdout.filter((r) => r.label === "benign");
  const caught = mal.filter((r) => !o.get(r.id)!.reachedApp).length;
  const fp = ben.filter((r) => !o.get(r.id)!.reachedApp).length;
  return { mal: mal.length, ben: ben.length, caught, missed: mal.length - caught, fp };
}
const sb = score(base);
const sl = score(withLearned);
const correct = (r: Labelled, o: Outcome) => (r.label === "malicious" ? !o.reachedApp : o.reachedApp);
const changed = holdout.filter((r) => base.get(r.id)!.lane !== withLearned.get(r.id)!.lane);
const pct = (a: number, b: number) => `${Math.round((a / b) * 100)}%`;

const md: string[] = [];
md.push("# Held-out evaluation", "");
md.push("Generated by `pnpm eval` (benchmarks/evaluate.ts). Do not edit by hand.", "");
md.push("Rules are learned from `baseline.har` (the 15 requests from `pnpm demo`) and tested on");
md.push(`\`holdout.json\`: ${holdout.length} labelled requests (${sb.ben} benign, ${sb.mal} malicious) that the learner never saw,`);
md.push("sent through a running gateway in front of a real app. A malicious request is **caught** if it");
md.push("never reaches the app. A benign request is a **false positive** if it doesn't reach the app.", "");
md.push("This is a small, hand-labelled set. It shows behaviour and failure cases; it is not a");
md.push("statistical accuracy claim.", "");
md.push("## Rules approved for this run", "");
md.push("Stand-in for human review: approve every proposal that was not rejected and is not already");
md.push("covered by the built-in rules.", "");
for (const p of approvedList) md.push(`- \`${p.kind} ${p.match}\`: ${p.severity}, ${p.confidence}, ${p.support.clients} clients, ${p.falsePositives.hits} false positives in training`);
if (approvedList.length === 0) md.push("- none");
md.push("", "## Results", "");
md.push("| Rules | Malicious caught | Missed | Benign wrongly stopped |");
md.push("|---|---|---|---|");
md.push(`| Built-in only | ${sb.caught}/${sb.mal} (${pct(sb.caught, sb.mal)}) | ${sb.missed} | ${sb.fp}/${sb.ben} (${pct(sb.fp, sb.ben)}) |`);
md.push(`| Built-in + learned | ${sl.caught}/${sl.mal} (${pct(sl.caught, sl.mal)}) | ${sl.missed} | ${sl.fp}/${sl.ben} (${pct(sl.fp, sl.ben)}) |`);
md.push("", `Requests whose outcome the learned rules changed: ${changed.length === 0 ? "none" : changed.map((r) => `\`${r.id}\``).join(", ")}.`, "");
md.push("## Every request", "");
md.push("| id | label | what it is | built-in | + learned | correct |");
md.push("|---|---|---|---|---|---|");
for (const r of holdout) {
  const a = base.get(r.id)!;
  const b = withLearned.get(r.id)!;
  md.push(`| ${r.id} | ${r.label} | ${r.note} | ${a.lane} | ${b.lane}${b.learnedFired ? " (learned rule)" : ""} | ${correct(r, b) ? "yes" : "**no**"} |`);
}
md.push("");
writeFileSync(new URL("RESULTS.md", here), md.join("\n"));

console.log(`learned from baseline.har: ${approvedList.map((p) => `${p.kind} ${p.match}`).join(", ") || "nothing"}`);
console.log(`held-out set: ${sb.ben} benign, ${sb.mal} malicious\n`);
console.log("rules                 caught        missed   benign wrongly stopped");
console.log(`built-in only         ${`${sb.caught}/${sb.mal}`.padEnd(13)} ${String(sb.missed).padEnd(8)} ${sb.fp}/${sb.ben}`);
console.log(`built-in + learned    ${`${sl.caught}/${sl.mal}`.padEnd(13)} ${String(sl.missed).padEnd(8)} ${sl.fp}/${sl.ben}`);
console.log("\nwrote benchmarks/RESULTS.md");
