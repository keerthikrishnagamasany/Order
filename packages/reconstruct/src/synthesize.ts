/**
 * Rule synthesis — ORDER's learning loop.
 *
 * Most bot defences stop at "blocked". ORDER goes one step further: it reads a captured
 * session and proposes NEW detection rules generalised from what hostile clients actually
 * did, each one carrying its evidence and checked against the legitimate traffic in the
 * same capture. A rule that would have matched a trusted or normal request is rejected
 * before a human ever sees it as a candidate.
 *
 * Principles:
 *   - Blame the locus that fired. If a request was blocked for an injection payload, the
 *     path it hit is not evidence against that path — only the payload is.
 *   - Evidence or it didn't happen. Every proposal lists the capture ordinals behind it.
 *   - False positives are checked, not assumed away. Zero benign matches IN THIS CAPTURE
 *     is necessary, not sufficient — so proposals are never auto-approved.
 *   - Authorized tests are excluded. A hired tester's probes are neither attack evidence
 *     nor legitimate traffic, so they can neither propose nor veto a rule.
 *   - Honest confidence. Synthesised rules top out at LIKELY; nothing learned is CERTAIN.
 *   - Generalise cautiously. A path-family rule (the directory a probed path lives in) is
 *     a guess beyond the evidence: it is always GUESSING and SUSPECT, so it can divert a
 *     request to the decoy but never block one. It needs two or more hostile clients, at
 *     least two path segments, and NO benign request anywhere under the family.
 */

import type { RequestFacts, RulePack, Signal } from "@order/core";

/** One request recovered from a capture, with ORDER's live verdict. */
export interface CapturedRequest {
  ordinal: number;
  ts: string;
  client: string;
  method: string;
  path: string;
  userAgent: string;
  status: number;
  lane: string;
  confidence: string;
  reasons: string[];
  /** Engagement label, when the request ran under an authorized security test. */
  authorizedTest?: string | undefined;
}

export type ProposalKind = "path" | "path_prefix" | "user_agent";

export interface RuleProposal {
  id: string;
  kind: ProposalKind;
  /** Exact path, path-family prefix ending in "/" (both case-insensitive), or user-agent product token. */
  match: string;
  severity: "HARD" | "SUSPECT";
  confidence: "LIKELY" | "GUESSING";
  support: { hits: number; clients: number; ordinals: number[] };
  falsePositives: { hits: number; ordinals: number[] };
  /** True when the existing rule pack already catches this, so the rule adds nothing. */
  redundant: boolean;
  status: "proposed" | "rejected";
  reason: string;
  /** Set to true by a human after review. Never set automatically. */
  approved: boolean;
}

const HOSTILE = new Set(["blocked", "decoy"]);
const BENIGN = new Set(["trusted", "normal"]);
/** Tokens too generic to ever be a useful UA rule. */
const GENERIC_UA = new Set(["mozilla"]);

/** Parse a HAR produced by ORDER (or any HAR carrying `_order`) into captured requests. */
export function fromHar(har: unknown): CapturedRequest[] {
  const entries = (har as { log?: { entries?: unknown[] } })?.log?.entries ?? [];
  const out: CapturedRequest[] = [];
  entries.forEach((raw, ordinal) => {
    const e = raw as {
      startedDateTime?: string;
      request?: { method?: string; url?: string; headers?: { name: string; value: string }[] };
      response?: { status?: number };
      _order?: { lane?: string; confidence?: string; reasons?: string[]; client?: string; authorizedTest?: string };
    };
    if (!e.request?.url || !e._order?.lane) return;
    let path = "/";
    try {
      path = new URL(e.request.url).pathname;
    } catch {
      /* keep "/" */
    }
    const headers = e.request.headers ?? [];
    const ua = headers.find((h) => h.name.toLowerCase() === "user-agent")?.value ?? "";
    const simClient = headers.find((h) => h.name.toLowerCase() === "x-sim-client")?.value;
    out.push({
      ordinal,
      ts: e.startedDateTime ?? "",
      client: e._order.client ?? simClient ?? "unknown",
      method: e.request.method ?? "GET",
      path,
      userAgent: ua,
      status: e.response?.status ?? 0,
      lane: e._order.lane,
      confidence: e._order.confidence ?? "GUESSING",
      reasons: e._order.reasons ?? [],
      authorizedTest: e._order.authorizedTest ?? testLabel(e._order.reasons ?? []),
    });
  });
  return out;
}

function testLabel(reasons: readonly string[]): string | undefined {
  const r = reasons.find((x) => x.startsWith("authorized_test:"));
  return r ? r.slice("authorized_test:".length) : undefined;
}

/** The product token of a user-agent, e.g. "sqlmap/1.7" -> "sqlmap". */
export function uaToken(ua: string): string | null {
  const m = /^([A-Za-z][A-Za-z0-9._-]*)\//.exec(ua.trim());
  return m ? (m[1] as string).toLowerCase() : null;
}

/** Did this request fire because of its payload (query/body) rather than its path? */
function payloadOnly(r: CapturedRequest): boolean {
  const payload = r.reasons.some((x) => x.includes("(query=") || x.includes("(body="));
  const path = r.reasons.some((x) => x.includes("(path="));
  return payload && !path;
}

function matches(kind: ProposalKind, match: string, r: CapturedRequest): boolean {
  if (kind === "path") return r.path.toLowerCase() === match;
  if (kind === "path_prefix") return r.path.toLowerCase().startsWith(match);
  return uaToken(r.userAgent) === match;
}

/** Minimum number of segments a path-family prefix must keep: "/a/b/" is the shortest allowed. */
const MIN_FAMILY_SEGMENTS = 2;

/** The family a path belongs to: its parent directory, e.g. "/wp-json/wp/v2/users" -> "/wp-json/wp/v2/". */
export function pathFamily(path: string): string | null {
  const segs = path.toLowerCase().split("/").filter(Boolean);
  if (segs.length - 1 < MIN_FAMILY_SEGMENTS) return null;
  return `/${segs.slice(0, -1).join("/")}/`;
}

function alreadyCaught(kind: ProposalKind, match: string, existing: RulePack | undefined): boolean {
  if (!existing) return false;
  const facts: RequestFacts = {
    method: "GET",
    path: kind === "path" ? match : kind === "path_prefix" ? `${match}x` : "/",
    query: "",
    body: "",
    userAgent: kind === "user_agent" ? `${match}/1.0` : "",
    clientId: "synthetic",
  };
  return existing.inspect(facts).length > 0;
}

export interface SynthesizeOptions {
  /** The pack already in use; proposals it already covers are flagged redundant. */
  existing?: RulePack;
}

export function synthesizeRules(reqs: CapturedRequest[], opts: SynthesizeOptions = {}): RuleProposal[] {
  // Authorized-test traffic is neither evidence of attack nor of legitimate use: a hired
  // tester's probes would otherwise count as "benign" and veto real rules.
  const scored = reqs.filter((r) => r.authorizedTest === undefined);
  const hostile = scored.filter((r) => HOSTILE.has(r.lane));
  const benign = scored.filter((r) => BENIGN.has(r.lane));

  // Candidate features, generalised from hostile requests only.
  const candidates = new Map<string, { kind: ProposalKind; match: string }>();
  for (const r of hostile) {
    if (!payloadOnly(r)) {
      const p = r.path.toLowerCase();
      candidates.set(`path:${p}`, { kind: "path", match: p });
      const fam = pathFamily(r.path);
      if (fam) candidates.set(`path_prefix:${fam}`, { kind: "path_prefix", match: fam });
    }
    const tok = uaToken(r.userAgent);
    if (tok && !GENERIC_UA.has(tok)) candidates.set(`user_agent:${tok}`, { kind: "user_agent", match: tok });
  }

  const proposals: RuleProposal[] = [];
  for (const { kind, match } of candidates.values()) {
    const sup = hostile.filter((r) => matches(kind, match, r) && !(kind !== "user_agent" && payloadOnly(r)));
    const fp = benign.filter((r) => matches(kind, match, r));
    const clients = new Set(sup.map((r) => r.client)).size;
    const allBlocked = sup.every((r) => r.lane === "blocked");

    const fpLanes = [...new Set(fp.map((r) => r.lane))].join("/");
    const family = kind === "path_prefix";
    // A family is only worth proposing when several clients support it.
    const rejected = fp.length > 0 || (family && clients < 2);
    const redundant = alreadyCaught(kind, match, opts.existing);

    proposals.push({
      id: `${kind}:${match}`,
      kind,
      match,
      severity: !family && allBlocked && clients >= 2 ? "HARD" : "SUSPECT",
      confidence: !family && clients >= 2 ? "LIKELY" : "GUESSING",
      support: { hits: sup.length, clients, ordinals: sup.map((r) => r.ordinal) },
      falsePositives: { hits: fp.length, ordinals: fp.map((r) => r.ordinal) },
      redundant,
      status: rejected ? "rejected" : "proposed",
      reason: fp.length > 0
        ? `would also match ${fp.length} ${fpLanes} request(s) in this capture`
        : rejected
          ? "a path family needs at least 2 hostile clients"
        : redundant
          ? "seen only from hostile clients, but the current pack already catches it"
          : family
            ? `generalised from ${new Set(sup.map((r) => r.path.toLowerCase())).size} probed path(s) by ${clients} clients; nothing benign under it in this capture. A guess: diverts, never blocks`
            : `seen only from hostile clients (${clients} client${clients === 1 ? "" : "s"}); no benign match in this capture`,
      approved: false,
    });
  }

  // Most useful first: proposed and novel, then by support.
  const rank = (p: RuleProposal) => (p.status === "proposed" ? 0 : 2) + (p.redundant ? 1 : 0);
  return proposals.sort((a, b) => rank(a) - rank(b) || b.support.clients - a.support.clients || b.support.hits - a.support.hits);
}

/**
 * Compile human-approved proposals into a RulePack. Only proposals with
 * `approved: true` AND `status: "proposed"` are included — a rejected proposal can't be
 * smuggled in by flipping `approved`.
 */
export function compileRules(proposals: readonly RuleProposal[], id = "learned"): RulePack {
  const active = proposals.filter((p) => p.approved && p.status === "proposed");
  const paths = new Map(active.filter((p) => p.kind === "path").map((p) => [p.match, p]));
  const uas = new Map(active.filter((p) => p.kind === "user_agent").map((p) => [p.match, p]));
  // Families never block, whatever a proposal says: a generalised rule is a guess.
  const families = active.filter((p) => p.kind === "path_prefix").sort((a, b) => b.match.length - a.match.length);
  return {
    id: `${id}@${active.length}`,
    inspect(facts: RequestFacts): Signal[] {
      const out: Signal[] = [];
      const p = paths.get(facts.path.toLowerCase());
      if (p) out.push({ name: "learned_path", severity: p.severity, where: "path", excerpt: facts.path.slice(0, 80) });
      else {
        const lower = facts.path.toLowerCase();
        const f = families.find((x) => lower.startsWith(x.match));
        if (f) out.push({ name: "learned_path_family", severity: "SUSPECT", where: "path", excerpt: facts.path.slice(0, 80) });
      }
      const tok = uaToken(facts.userAgent);
      const u = tok ? uas.get(tok) : undefined;
      if (u) out.push({ name: "learned_user_agent", severity: u.severity, where: "header", excerpt: tok as string });
      return out;
    },
  };
}
