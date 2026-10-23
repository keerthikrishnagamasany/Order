/**
 * Scoring configuration. A single SUSPECT signal shouldn't always trap a client — a real
 * user can trip one. ORDER accumulates a score per client; sustained suspicious behaviour
 * crosses into the decoy lane. Scores expire, so a client flagged once is not flagged
 * forever. Storage lives behind `StateStore` (see state.ts).
 */

export interface ScoringConfig {
  /** Score at or above which an unknown client is routed to the decoy lane. */
  readonly decoyThreshold: number;
  /** Points added for a SUSPECT signal on a request. */
  readonly suspectPoints: number;
  /** Rate window in milliseconds. */
  readonly rateWindowMs: number;
  /** Max requests per window before the client is treated as rate-abusive. */
  readonly rateMax: number;
  /** How long a score lives after the client's last suspicious request. Default 1h. */
  readonly scoreTtlMs?: number;
}

export const DEFAULT_SCORING: ScoringConfig = {
  decoyThreshold: 3,
  suspectPoints: 2,
  rateWindowMs: 10_000,
  rateMax: 40,
  scoreTtlMs: 60 * 60 * 1000,
};
