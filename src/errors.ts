/** Why a token, a key or a key set was refused. Each refusal has a code a caller can branch on. */
export type JwksErrorCode =
  | "ERR_JWT_MALFORMED"          // not three base64url parts of JSON, or over the size limit
  | "ERR_JWS_ALGORITHM"          // the header's alg is not one the caller accepts ("none" never is)
  | "ERR_JWS_UNSUPPORTED"        // a crit header, or b64: false
  | "ERR_JWS_SIGNATURE"          // the signature does not verify
  | "ERR_JWK_NO_MATCH"           // no key of the set fits the header (kid, alg, key type)
  | "ERR_JWK_INVALID"            // a key that cannot verify this algorithm (type, curve, size)
  | "ERR_JWKS_FETCH"             // the key set could not be fetched or read
  | "ERR_JWT_EXPIRED"            // exp has passed
  | "ERR_JWT_NOT_YET_VALID"      // nbf (or iat) is in the future
  | "ERR_JWT_CLAIM"              // iss, aud, sub, typ, a required claim, or a scope does not hold
  | "ERR_DISCOVERY"              // the authorization server's metadata could not be read, or names another issuer
  | "ERR_INTROSPECTION";         // the introspection endpoint failed

export class JwksError extends Error {
  readonly code: JwksErrorCode;
  /** For ERR_JWT_CLAIM: the claim that did not hold. */
  readonly claim: string | undefined;
  constructor(code: JwksErrorCode, message: string, options: { claim?: string; cause?: unknown } = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = "JwksError";
    this.code = code;
    this.claim = options.claim;
  }
}
