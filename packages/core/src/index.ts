/** @order/core — the ORDER framework surface. */
export type {
  Lane,
  Confidence,
  Severity,
  Locus,
  Signal,
  RequestFacts,
  RulePack,
  Decision,
  AuthorizedTester,
  ClientState,
} from "./types.js";
export { normalise, normaliseWithInfo, normalisePath, urlDecodeDeep, DEFAULT_INSPECTION_LIMIT, type Normalised } from "./normalise.js";
export { CanaryRegistry, canaryCandidates, type Canary, type CanaryOptions, type CanaryScan } from "./canary.js";
export { DEFAULT_SCORING, type ScoringConfig } from "./scoring.js";
export {
  MemoryStateStore,
  RedisStateStore,
  isPromise,
  type StateStore,
  type MemoryStateOptions,
  type RedisStateOptions,
  type RedisExec,
  type MaybePromise,
} from "./state.js";
export { Engine, type EngineConfig, type RawRequest } from "./pipeline.js";
export { combine } from "./combine.js";
export {
  HarRecorder,
  toHarEntry,
  REDACTED_HEADERS,
  KEPT_HEADERS,
  type CapturePolicy,
  type HarEntry,
  type HarRecorderOptions,
  type CaptureInput,
} from "./capture.js";
