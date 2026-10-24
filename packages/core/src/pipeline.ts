/**
 * The live decision pipeline. This is the fast path — it runs on every request and must
 * stay cheap. Deep analysis happens offline in @order/reconstruct, never here.
 *
 * Order of checks is deliberate:
 *   1. Canary replay   -> blocked, CERTAIN   (provable compromise, beats everything)
 *   2. Trusted identity-> trusted            (unless it carries a HARD signal: likely leaked,
 *                                             except during an active, in-scope authorized test)
 *   3. HARD signal     -> blocked, LIKELY
 *   4. SUSPECT / score -> decoy, GUESSING
 *   5. otherwise       -> normal
 *
 * The logic is written once, split around the two points that touch state (canary
 * lookup, then rate/score update). `decide()` runs it against a synchronous store with no
 * I/O; `decideAsync()` runs the identical logic against any store, including Redis.
 */

import { CanaryRegistry } from "./canary.js";
import { normalise } from "./normalise.js";
import { DEFAULT_SCORING, type ScoringConfig } from "./scoring.js";
import { isPromise, MemoryStateStore, type StateStore } from "./state.js";
import type { AuthorizedTester, Decision, Lane, RequestFacts, RulePack, Severity, Signal } from "./types.js";

export interface RawRequest {
  method: string;
  path: string;
  query?: string | undefined;
  body?: string | undefined;
  userAgent?: string | undefined;
  identity?: string | undefined;
  clientId: string;
  /** Set by an upstream verifier (e.g. @order/web-bot-auth): the verified agent's origin. */
  verifiedAgent?: string | undefined;
  /** Signals raised outside the rule pack, e.g. a forged agent signature. */
  extraSignals?: readonly Signal[] | undefined;
}

export interface EngineConfig {
  readonly rules: RulePack;
  /** Identities accepted into the trusted lane, mapped to a human label. */
  readonly allowlist: ReadonlyMap<string, string>;
  readonly canaries: CanaryRegistry;
  /**
   * Authorized security tests, keyed by identity or `agent:<origin>`. The client must also
   * be trusted (allowlist or verified agent); this map alone grants nothing.
   */
  readonly authorizedTesters?: ReadonlyMap<string, AuthorizedTester>;
  readonly scoring?: ScoringConfig;
  /** Where scores and rate windows live. Default: in-memory (synchronous). */
  readonly state?: StateStore;
  /** Clock, injectable for tests. */
  readonly now?: () => number;
}

function worst(signals: readonly Signal[]): Severity | null {
  const rank: Record<Severity, number> = { HARD: 3, SUSPECT: 2, SOFT: 1 };
  let best: Severity | null = null;
  for (const s of signals) if (best === null || rank[s.severity] > rank[best]) best = s.severity;
  return best;
}

/** Result of the stateless part: either a final decision, or "needs scoring". */
type Pending =
  | { done: Decision }
  | { done?: undefined; clientId: string; sev: Severity | null; signals: Signal[]; reasons: string[] };

const decision = (
  lane: Lane,
  status: number,
  confidence: Decision["confidence"],
  signals: readonly Signal[],
  reasons: readonly string[],
): Decision => ({ lane, status, confidence, signals, reasons });

export class Engine {
  private readonly state: StateStore;
  private readonly scoring: ScoringConfig;
  private readonly now: () => number;

  constructor(private readonly cfg: EngineConfig) {
    this.state = cfg.state ?? new MemoryStateStore();
    this.scoring = { ...DEFAULT_SCORING, ...(cfg.scoring ?? {}) };
    this.now = cfg.now ?? Date.now;
    for (const [key, t] of cfg.authorizedTesters ?? []) {
      if (!Number.isFinite(t.expiresAt)) throw new Error(`authorized tester "${key}" needs a finite expiresAt`);
      if (!t.label) throw new Error(`authorized tester "${key}" needs a label`);
    }
  }

  private factsOf(req: RawRequest): RequestFacts {
    return {
      method: req.method,
      path: req.path,
      query: normalise(req.query),
      body: normalise(req.body),
      userAgent: req.userAgent ?? "",
      identity: req.identity,
      clientId: req.clientId,
    };
  }

  /** Everything up to the rate/score step. `canaryOrigin` is the result of the lookup. */
  private before(req: RawRequest, facts: RequestFacts, canaryOrigin: string | null): Pending {
    const signals = [...this.cfg.rules.inspect(facts), ...(req.extraSignals ?? [])];
    const reasons = signals.map((s) => `${s.name}:${s.severity}(${s.where}='${s.excerpt}')`);

    if (canaryOrigin !== null) {
      reasons.push(`canary_replayed:${canaryOrigin}`);
      return { done: decision("blocked", 403, "CERTAIN", signals, reasons) };
    }

    const sev = worst(signals);
    const allowlisted = req.identity ? this.cfg.allowlist.get(req.identity) : undefined;
    const label = allowlisted ?? (req.verifiedAgent ? `agent:${req.verifiedAgent}` : undefined);
    if (label !== undefined) {
      const test = this.authorizedTest(req, facts.path, reasons);
      if (test !== undefined) {
        reasons.push(`authorized_test:${test}`);
        return { done: { ...decision("trusted", 200, "CERTAIN", signals, reasons), authorizedTest: test } };
      }
      if (sev === "HARD") {
        reasons.push(`trusted_key_hard_signal:${label}`);
        return { done: decision("blocked", 403, "LIKELY", signals, reasons) };
      }
      if (allowlisted === undefined && req.verifiedAgent) reasons.push(`verified_agent:${req.verifiedAgent}`);
      return { done: decision("trusted", 200, "CERTAIN", signals, reasons) };
    }

    if (sev === "HARD") return { done: decision("blocked", 403, "LIKELY", signals, reasons) };
    return { clientId: facts.clientId, sev, signals, reasons };
  }

  /** The final step, given the client's request count and score after this request. */
  private after(p: Exclude<Pending, { done: Decision }>, hits: number, score: number): Decision {
    const rateHit = hits > this.scoring.rateMax;
    if (rateHit) p.reasons.push("rate_exceeded");
    if (p.sev === "SUSPECT" || score >= this.scoring.decoyThreshold) {
      p.reasons.push(`score=${score}`);
      return decision("decoy", 200, "GUESSING", p.signals, p.reasons);
    }
    return decision("normal", 200, "CERTAIN", p.signals, p.reasons);
  }

  /**
   * The active engagement for this trusted client, or undefined. A tester entry is keyed
   * by the presented identity or by `agent:<origin>`. An expired or out-of-scope entry
   * leaves a reason in the log and falls back to normal trusted handling.
   */
  private authorizedTest(req: RawRequest, path: string, reasons: string[]): string | undefined {
    const testers = this.cfg.authorizedTesters;
    if (!testers || testers.size === 0) return undefined;
    const t =
      (req.identity !== undefined ? testers.get(req.identity) : undefined) ??
      (req.verifiedAgent !== undefined ? testers.get(`agent:${req.verifiedAgent}`) : undefined);
    if (!t) return undefined;
    if (this.now() >= t.expiresAt) {
      reasons.push(`authorized_test_expired:${t.label}`);
      return undefined;
    }
    if (t.paths && !t.paths.some((p) => path === p || path.startsWith(p.endsWith("/") ? p : `${p}/`))) {
      reasons.push(`authorized_test_out_of_scope:${t.label}`);
      return undefined;
    }
    return t.label;
  }

  private points(sev: Severity | null, hits: number): number {
    return (sev === "SUSPECT" ? this.scoring.suspectPoints : 0) + (hits > this.scoring.rateMax ? 1 : 0);
  }

  /** Synchronous decision. Requires a synchronous state store (the default). */
  decide(req: RawRequest): Decision {
    const facts = this.factsOf(req);
    const hit = this.cfg.canaries.detect(`${facts.query} ${facts.body} ${facts.identity ?? ""}`);
    const p = this.before(req, facts, hit?.origin ?? null);
    if (p.done) return p.done;

    const now = this.now();
    const hits = this.state.hit(p.clientId, now, this.scoring.rateWindowMs, this.scoring.rateMax);
    if (isPromise(hits)) throw new Error("Engine.decide() needs a synchronous state store; use decideAsync()");
    const pts = this.points(p.sev, hits);
    const score = pts > 0 ? this.state.addScore(p.clientId, pts, now, this.ttl()) : this.state.getScore(p.clientId, now);
    if (isPromise(score)) throw new Error("Engine.decide() needs a synchronous state store; use decideAsync()");
    return this.after(p, hits, score);
  }

  /** Decision against any state store, including shared asynchronous ones like Redis. */
  async decideAsync(req: RawRequest): Promise<Decision> {
    const facts = this.factsOf(req);
    const hit = await this.cfg.canaries.detectAsync(`${facts.query} ${facts.body} ${facts.identity ?? ""}`);
    const p = this.before(req, facts, hit?.origin ?? null);
    if (p.done) return p.done;

    const now = this.now();
    const hits = await this.state.hit(p.clientId, now, this.scoring.rateWindowMs, this.scoring.rateMax);
    const pts = this.points(p.sev, hits);
    const score = pts > 0 ? await this.state.addScore(p.clientId, pts, now, this.ttl()) : await this.state.getScore(p.clientId, now);
    return this.after(p, hits, score);
  }

  private ttl(): number {
    return this.scoring.scoreTtlMs ?? 60 * 60 * 1000;
  }
}
