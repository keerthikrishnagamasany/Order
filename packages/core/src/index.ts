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
  ClientState,
} from "./types.js";
export { normalise, urlDecodeDeep } from "./normalise.js";
export { CanaryRegistry, canaryCandidates, type Canary, type CanaryOptions } from "./canary.js";
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
  type HarEntry,
  type HarRecorderOptions,
  type CaptureInput,
} from "./capture.js";
