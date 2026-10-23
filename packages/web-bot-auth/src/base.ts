/**
 * RFC 9421 signature base construction (Section 2.5).
 *
 * The base is the exact byte string the signer signed and the verifier re-creates.
 * Each covered component becomes one line `"<name>"<params>: <value>`, and the final
 * line is `"@signature-params": <the serialized params>`. Lines are joined with LF.
 * Getting a single byte wrong fails verification, which is the point — so this mirrors
 * the signer's derivation precisely for the components Web Bot Auth uses.
 */

import type { CoveredComponent, SignatureInput } from "./structured.js";

export interface MessageContext {
  method: string;
  /** Authority (host[:port]) exactly as the request targets it, lowercased host. */
  authority: string;
  path: string;
  targetUri: string;
  /** Serialized Signature-Agent dictionary member value for the signature's label. */
  signatureAgentValue: string;
}

function derive(component: CoveredComponent, ctx: MessageContext): string | null {
  switch (component.name) {
    case "@method":
      return ctx.method.toUpperCase();
    case "@authority":
      return ctx.authority.toLowerCase();
    case "@path":
      return ctx.path;
    case "@target-uri":
      return ctx.targetUri;
    case "signature-agent":
      // Dictionary-member component: value is the serialized member for the given key.
      return ctx.signatureAgentValue;
    default:
      // Unsupported component — refuse rather than sign over an empty value.
      return null;
  }
}

/**
 * Build the signature base. Returns null if any covered component can't be derived
 * (which must make the whole verification fail, not silently skip the component).
 */
export function buildSignatureBase(input: SignatureInput, ctx: MessageContext): string | null {
  const lines: string[] = [];
  for (const comp of input.components) {
    const value = derive(comp, ctx);
    if (value === null) return null;
    lines.push(`"${comp.name}"${comp.rawParams}: ${value}`);
  }
  lines.push(`"@signature-params": ${input.rawValue}`);
  return lines.join("\n");
}
