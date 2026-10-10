/*
 * A JWK as a verification key, and which algorithm a key may verify. A key is only ever used with the algorithms of
 * its own type: an RSA key never verifies an HMAC (the "algorithm confusion" that lets a public key act as a secret),
 * an EC key only the curve's own ES*, an OKP key only EdDSA.
 */
import { createPublicKey, createSecretKey, type KeyObject } from "node:crypto";
import { JwksError } from "./errors.ts";

export type Algorithm =
  | "RS256" | "RS384" | "RS512"
  | "PS256" | "PS384" | "PS512"
  | "ES256" | "ES384" | "ES512"
  | "EdDSA" | "Ed25519"
  | "HS256" | "HS384" | "HS512";

/** The asymmetric algorithms, the default of every verification against a key set. */
export const ASYMMETRIC: readonly Algorithm[] = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA", "Ed25519"];
export const ALGORITHMS: readonly Algorithm[] = [...ASYMMETRIC, "HS256", "HS384", "HS512"];

/** A public JSON Web Key (RFC 7517), as a key set serves it. */
export interface Jwk {
  kty: string;
  kid?: string;
  alg?: string;
  use?: string;
  key_ops?: string[];
  crv?: string;
  n?: string;
  e?: string;
  x?: string;
  y?: string;
  k?: string;
  d?: string;
  [member: string]: unknown;
}

const EC_CURVES: Record<string, string> = { ES256: "prime256v1", ES384: "secp384r1", ES512: "secp521r1" };
const MIN_RSA_BITS = 2048;
const MIN_HMAC_BYTES: Record<string, number> = { HS256: 32, HS384: 48, HS512: 64 };

/** Whether `key` may verify `alg`; throws ERR_JWK_INVALID when it may not, naming why. */
export function assertKeyFits(key: KeyObject, alg: Algorithm): void {
  const details = key.asymmetricKeyDetails;
  if (alg.startsWith("HS")) {
    if (key.type !== "secret") throw new JwksError("ERR_JWK_INVALID", `${alg} needs a secret key, not a ${key.asymmetricKeyType ?? key.type} key`);
    if ((key.symmetricKeySize ?? 0) < MIN_HMAC_BYTES[alg]!) throw new JwksError("ERR_JWK_INVALID", `${alg} needs a secret of ${MIN_HMAC_BYTES[alg]} bytes or more`);
    return;
  }
  if (key.type !== "public") throw new JwksError("ERR_JWK_INVALID", `${alg} needs a public key, not a ${key.type} key`);
  const type = key.asymmetricKeyType;
  if (alg.startsWith("RS")) {
    if (type !== "rsa") throw new JwksError("ERR_JWK_INVALID", `${alg} needs an RSA key, not ${type}`);
  } else if (alg.startsWith("PS")) {
    if (type !== "rsa" && type !== "rsa-pss") throw new JwksError("ERR_JWK_INVALID", `${alg} needs an RSA key, not ${type}`);
  } else if (alg.startsWith("ES")) {
    if (type !== "ec" || details?.namedCurve !== EC_CURVES[alg]) throw new JwksError("ERR_JWK_INVALID", `${alg} needs an EC key on ${EC_CURVES[alg]}, not ${type}${details?.namedCurve ? ` on ${details.namedCurve}` : ""}`);
    return;
  } else if (alg === "EdDSA") {
    if (type !== "ed25519" && type !== "ed448") throw new JwksError("ERR_JWK_INVALID", `EdDSA needs an Ed25519 or Ed448 key, not ${type}`);
    return;
  } else if (alg === "Ed25519") {
    if (type !== "ed25519") throw new JwksError("ERR_JWK_INVALID", `Ed25519 needs an Ed25519 key, not ${type}`);
    return;
  }
  if ((details?.modulusLength ?? 0) < MIN_RSA_BITS) throw new JwksError("ERR_JWK_INVALID", `${alg} needs an RSA key of ${MIN_RSA_BITS} bits or more, this one has ${details?.modulusLength}`);
}

/** The algorithms a JWK may verify, from its kty and crv (and its alg, when it names one). */
export function algorithmsOf(jwk: Jwk): Algorithm[] {
  const fits: Algorithm[] = jwk.kty === "RSA" ? ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"]
    : jwk.kty === "EC" ? ({ "P-256": ["ES256"], "P-384": ["ES384"], "P-521": ["ES512"] } as Record<string, Algorithm[]>)[jwk.crv ?? ""] ?? []
    : jwk.kty === "OKP" ? (jwk.crv === "Ed25519" ? ["EdDSA", "Ed25519"] : jwk.crv === "Ed448" ? ["EdDSA"] : [])
    : jwk.kty === "oct" ? ["HS256", "HS384", "HS512"] : [];
  return jwk.alg ? fits.filter((a) => a === jwk.alg) : fits;
}

/** Whether a key set's JWK is for verifying signatures: no "use" or "sig", no key_ops or one holding "verify". */
export function isSigningKey(jwk: Jwk): boolean {
  if (jwk.use !== undefined && jwk.use !== "sig") return false;
  if (jwk.key_ops !== undefined && !(Array.isArray(jwk.key_ops) && jwk.key_ops.includes("verify"))) return false;
  return true;
}

/** A JWK as a KeyObject. A key set's JWK with private members (d) is refused: a key set publishes public keys only. */
export function importJwk(jwk: Jwk): KeyObject {
  if (!jwk || typeof jwk !== "object" || typeof jwk.kty !== "string") throw new JwksError("ERR_JWK_INVALID", "a JWK is an object with kty");
  try {
    if (jwk.kty === "oct") {
      if (typeof jwk.k !== "string") throw new Error("an oct key needs k");
      return createSecretKey(Buffer.from(jwk.k, "base64url"));
    }
    if (jwk.d !== undefined) throw new Error("it holds a private key (d)");
    /* Only the members node:crypto reads: a key set's extra members (x5c, x5t…) never reach it. */
    const { kty, crv, n, e, x, y } = jwk;
    return createPublicKey({ key: { kty, crv, n, e, x, y } as never, format: "jwk" });
  } catch (cause) {
    throw new JwksError("ERR_JWK_INVALID", `the ${jwk.kty} key${jwk.kid ? ` ${jwk.kid}` : ""} cannot be read: ${(cause as Error).message}`, { cause });
  }
}
