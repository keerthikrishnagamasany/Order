/**
 * Signer for Web Bot Auth requests.
 *
 * This is the agent-operator side of the standard: an agent signs its own outgoing
 * requests so sites can verify who it is. ORDER ships it so adopters can test their
 * verification end to end, and so agent builders can
 * present a verifiable identity to sites that run ORDER or any other conforming verifier.
 */

import { sign as edSign, type KeyObject } from "node:crypto";
import { buildSignatureBase } from "./base.js";
import { parseSignatureInput } from "./structured.js";
import { ed25519Thumbprint, type JwkOkp } from "./thumbprint.js";

export interface SignOptions {
  privateKey: KeyObject;
  publicJwk: JwkOkp;
  /** The agent's key-directory URL, sent as Signature-Agent. Must be https. */
  agentUrl: string;
  /** host[:port] of the target, exactly as the request will carry it. */
  authority: string;
  label?: string;
  createdSec?: number;
  ttlSec?: number;
}

export interface SignedHeaders {
  "signature-input": string;
  signature: string;
  "signature-agent": string;
}

export function signWebBotAuth(o: SignOptions): SignedHeaders {
  const label = o.label ?? "sig";
  const created = o.createdSec ?? Math.floor(Date.now() / 1000);
  const expires = created + (o.ttlSec ?? 300);
  const keyid = ed25519Thumbprint(o.publicJwk);
  const agentValue = `"${o.agentUrl}"`;

  const inputValue =
    `("@authority" "signature-agent";key="${label}")` +
    `;created=${created};expires=${expires};keyid="${keyid}";alg="ed25519";tag="web-bot-auth"`;
  const signatureInput = `${label}=${inputValue}`;

  const parsed = parseSignatureInput(signatureInput, label);
  if (!parsed) throw new Error("internal: failed to parse generated Signature-Input");

  const base = buildSignatureBase(parsed, {
    method: "GET",
    authority: o.authority,
    path: "/",
    targetUri: `https://${o.authority}/`,
    signatureAgentValue: agentValue,
  });
  if (base === null) throw new Error("internal: failed to build signature base");

  const sig = edSign(null, Buffer.from(base, "utf8"), o.privateKey);
  return {
    "signature-input": signatureInput,
    signature: `${label}=:${sig.toString("base64")}:`,
    "signature-agent": `${label}=${agentValue}`,
  };
}
