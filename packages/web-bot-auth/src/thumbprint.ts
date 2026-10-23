/**
 * JWK SHA-256 thumbprints.
 *
 * Web Bot Auth requires `keyid` to be a base64url JWK thumbprint — RFC 7638 for
 * RSA/EC, RFC 8037 Appendix A.3 for Ed25519 (OKP). The thumbprint is computed over
 * the required members only, with lexicographically sorted keys and no whitespace.
 * We verify that a resolved key's thumbprint matches the presented `keyid`, so a
 * directory can't hand us a key under the wrong id.
 */

import { createHash } from "node:crypto";

export interface JwkOkp {
  kty: "OKP";
  crv: string; // "Ed25519"
  x: string; // base64url public key
  [k: string]: unknown;
}

function b64url(buf: Buffer): string {
  return buf.toString("base64url");
}

/** RFC 8037 A.3 thumbprint for an Ed25519 (OKP) JWK. */
export function ed25519Thumbprint(jwk: JwkOkp): string {
  // Required members for OKP, in lexicographic order: crv, kty, x
  const canonical = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}"}`;
  return b64url(createHash("sha256").update(canonical).digest());
}

export function thumbprintMatches(jwk: JwkOkp, keyid: string): boolean {
  try {
    return ed25519Thumbprint(jwk) === keyid;
  } catch {
    return false;
  }
}
