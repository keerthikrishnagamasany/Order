/**
 * Core vocabulary of ORDER. Everything else is built on these types.
 *
 * ORDER sorts every inbound request into exactly one {@link Lane}. The decision is
 * made live, in the request path, from {@link Signal}s raised by detector packs plus
 * a per-client score. Intent is always *inferred* from behaviour, so every
 * conclusion carries a {@link Confidence} and the evidence behind it.
 */

/** Where a request ends up. The whole system is a function that returns one of these. */
export type Lane =
  | "trusted" // allowlisted / cryptographically verified agent; served real data, still watched
  | "normal" // unknown but clean; served ordinary public data
  | "decoy" // suspicious but unconfirmed; served convincing fake data seeded with canaries
  | "blocked"; // a hard signal or a replayed canary; denied

/** How sure ORDER is of a claim. Never fabricated — only a canary replay earns CERTAIN. */
export type Confidence = "CERTAIN" | "LIKELY" | "GUESSING";

/** Severity of a single detection. Drives the lane and the per-client score. */
export type Severity = "HARD" | "SUSPECT" | "SOFT";

/** Which part of the request a detector matched. */
export type Locus = "path" | "query" | "body" | "header" | "identity";

/** One thing a detector noticed about one request. Immutable evidence. */
export interface Signal {
  /** Stable detector id, e.g. "sql_injection". */
  readonly name: string;
  readonly severity: Severity;
  readonly where: Locus;
  /** Short, already-truncated excerpt safe to log. Never the full payload. */
  readonly excerpt: string;
}

/** The normalised, decoded view of a request that detectors inspect. */
export interface RequestFacts {
  readonly method: string;
  readonly path: string;
  /** URL-decoded (recursively) query string. Detectors must see decoded input. */
  readonly query: string;
  /** URL-decoded request body (bounded). */
  readonly body: string;
  readonly userAgent: string;
  /** A presented credential/identity token, if any (e.g. an MCP key). */
  readonly identity?: string | undefined;
  /** Opaque, stable id for the originating client (source IP + presented identity in prod). */
  readonly clientId: string;
}

/** A detector pack: the pluggable unit. The public repo ships a reference pack;
 *  a private, tuned pack can replace or extend it without touching the framework. */
export interface RulePack {
  readonly id: string;
  /** Pure: given one request's facts, return every signal that fired. No side effects. */
  inspect(facts: RequestFacts): Signal[];
}

/** The verdict ORDER reaches for one request, with the evidence that produced it. */
export interface Decision {
  readonly lane: Lane;
  readonly status: number;
  readonly confidence: Confidence;
  readonly signals: readonly Signal[];
  /** Human-readable evidence strings, for the decision log and offline reconstruction. */
  readonly reasons: readonly string[];
  /** Label of the authorized test engagement this request ran under, if any. */
  readonly authorizedTest?: string | undefined;
}

/**
 * A time-boxed, explicitly authorized security test (a pen-test, a red-team exercise, your
 * own scanner). Applies only to a client that is ALREADY trusted (allowlisted key or
 * verified agent). While active and in scope, its attack payloads are logged and allowed
 * through instead of being treated as a leaked key. A canary replay still blocks.
 */
export interface AuthorizedTester {
  /** Human label for the engagement, e.g. "Q4 external pen-test". Appears in logs. */
  readonly label: string;
  /** Epoch ms after which the authorization lapses. Required: there is no open-ended mode. */
  readonly expiresAt: number;
  /** Path prefixes the test may touch. Omit to allow every path. */
  readonly paths?: readonly string[];
}

/** Per-client state carried across a session. Kept small and serialisable. */
export interface ClientState {
  score: number;
  lastLane: Lane | null;
  hits: number[]; // monotonic timestamps (ms) within the rate window
}
