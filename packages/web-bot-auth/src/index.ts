/**
 * @order/web-bot-auth — verify (and sign) Web Bot Auth requests.
 *
 * Implements the verifier side of draft-ietf-webbotauth-httpsig-protocol on top of
 * RFC 9421 HTTP Message Signatures, Ed25519 keys, and RFC 8037 JWK thumbprints.
 * Zero runtime dependencies; key resolution is injected.
 */
export {
  verifyWebBotAuth,
  StaticKeyResolver,
  type KeyResolver,
  type VerifyResult,
  type VerifyStatus,
  type VerifyOptions,
  type RequestHeaders,
} from "./verify.js";
export { signWebBotAuth, type SignOptions, type SignedHeaders } from "./sign.js";
export {
  HttpsDirectoryResolver,
  httpsTransport,
  parseDirectory,
  DIRECTORY_PATH,
  DIRECTORY_MEDIA_TYPE,
  type DirectoryResolverOptions,
  type Transport,
  type TransportResponse,
} from "./directory.js";
export { isPrivateAddress, isHttpsOrigin, guardedLookup } from "./netguard.js";
export { ed25519Thumbprint, thumbprintMatches, type JwkOkp } from "./thumbprint.js";
export { buildSignatureBase, type MessageContext } from "./base.js";
export {
  parseSignatureInput,
  parseSignature,
  parseSignatureAgent,
  type SignatureInput,
  type CoveredComponent,
} from "./structured.js";
