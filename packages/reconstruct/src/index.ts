/** @order/reconstruct — offline session reconstruction via the REA CLI. */
export {
  reaAvailable,
  inspectCapture,
  apiSurface,
  type ReaCaptureResult,
  type ReaApiSurface,
} from "./rea.js";
export {
  fromHar,
  synthesizeRules,
  compileRules,
  uaToken,
  pathFamily,
  type CapturedRequest,
  type RuleProposal,
  type ProposalKind,
  type SynthesizeOptions,
} from "./synthesize.js";
export {
  buildVerdicts,
  type DecisionLogEntry,
  type Hypothesis,
  type ClientVerdict,
} from "./verdict.js";
