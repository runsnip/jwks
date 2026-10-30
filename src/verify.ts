/*
 * verifyJwt: a JWT in JWS compact serialization (RFC 7515, 7519), checked in this order, each step refusing with its
 * own code:
 * 1. shape: a string under maxTokenLength, three parts of strict base64url (no padding, no other character), a header
 *    and a payload that are JSON objects;
 * 2. header: an alg the caller accepts ("none" never is), no crit (no extension is understood), no b64: false;
 * 3. signature: against the keys that fit the header (a key set's, by kid and key type; or the key given), each key
 *    checked to fit the algorithm (type, curve, size) before it is used, an ECDSA signature of exactly its curve's
 *    length, an HMAC compared in constant time;
 * 4. claims: exp, nbf (and iat with maxTokenAgeS) with clockToleranceS of leeway; iss, aud, sub, typ and required
 *    claims as the caller asks.
 */
import { constants, createHmac, timingSafeEqual, verify as verifySignature, type KeyObject } from "node:crypto";
import { strictEd25519 } from "./ed25519.ts";
import { JwksError } from "./errors.ts";
import { type Algorithm, type Jwk, ASYMMETRIC, assertKeyFits, importJwk } from "./jwk.ts";
import type { JwsHeader, KeySet } from "./jwks.ts";

export interface JwtPayload {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  [claim: string]: unknown;
}

export interface VerifyOptions {
  /** The algorithms accepted (default: the asymmetric ones; an HMAC is accepted only when named here). */
  algorithms?: readonly Algorithm[];
  /** The token's iss must be this (or one of these). */
  issuer?: string | readonly string[];
  /** The token's aud must hold this (or one of these). */
  audience?: string | readonly string[];
  /** The token's sub must be this. */
  subject?: string;
  /** The header's typ must be this ("at+jwt" matches "application/at+jwt", case aside). */
  typ?: string;
  /** Seconds of leeway on exp, nbf and iat (default 0). */
  clockToleranceS?: number;
  /** The most seconds since iat (iat is then required). */
  maxTokenAgeS?: number;
  /** Claims that must be present. */
  requiredClaims?: readonly string[];
  /** The time to check against (default: now). */
  currentDate?: Date;
  /** A longer token is refused before anything is decoded (default 16 384 characters). */
  maxTokenLength?: number;
}

export interface VerifiedJwt {
  header: JwsHeader;
  payload: JwtPayload;
}

/** What a token is checked against: a key set, a KeyObject, a JWK, or a secret (HMAC). */
export type VerificationKey = KeySet | KeyObject | Jwk | Uint8Array;

const B64URL = /^[A-Za-z0-9_-]*$/;
const HASH: Record<Algorithm, string | null> = {
  RS256: "sha256", RS384: "sha384", RS512: "sha512", PS256: "sha256", PS384: "sha384", PS512: "sha512",
  ES256: "sha256", ES384: "sha384", ES512: "sha512", EdDSA: null, Ed25519: null, HS256: "sha256", HS384: "sha384", HS512: "sha512",
};
const ECDSA_BYTES: Partial<Record<Algorithm, number>> = { ES256: 64, ES384: 96, ES512: 132 };

const malformed = (message: string) => new JwksError("ERR_JWT_MALFORMED", message);
const claimError = (claim: string, message: string) => new JwksError("ERR_JWT_CLAIM", message, { claim });

function decodeJson(part: string, what: string): Record<string, unknown> {
  let value: unknown;
  try { value = JSON.parse(Buffer.from(part, "base64url").toString("utf8")); } catch { throw malformed(`the ${what} is not base64url JSON`); }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw malformed(`the ${what} is not a JSON object`);
  return value as Record<string, unknown>;
}

const raws = new WeakMap<KeyObject, Buffer>();
/** An Ed25519 KeyObject's 32 public bytes, exported once per key. */
function rawEd25519(key: KeyObject): Buffer {
  let raw = raws.get(key);
  if (!raw) raws.set(key, (raw = Buffer.from(key.export({ format: "jwk" }).x!, "base64url")));
  return raw;
}

/** Whether `signature` verifies `data` with `key` under `alg` (the key already checked to fit). */
export function verifies(alg: Algorithm, key: KeyObject, data: Buffer, signature: Buffer): boolean {
  const hash = HASH[alg];
  if (alg.startsWith("HS")) {
    const expected = createHmac(hash!, key).update(data).digest();
    return expected.length === signature.length && timingSafeEqual(expected, signature);
  }
  try {
    if (alg.startsWith("ES")) {
      if (signature.length !== ECDSA_BYTES[alg]) return false;
      return verifySignature(hash, data, { key, dsaEncoding: "ieee-p1363" }, signature);
    }
    if (key.asymmetricKeyType === "ed25519" && !strictEd25519(rawEd25519(key), signature)) return false;
    if (alg.startsWith("PS")) return verifySignature(hash, data, { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST }, signature);
    return verifySignature(hash, data, key, signature);
  } catch {
    return false;
  }
}

function isKeySet(key: VerificationKey): key is KeySet {
  return typeof (key as KeySet).getKeys === "function";
}

function keyObjectOf(key: Exclude<VerificationKey, KeySet>): KeyObject {
  if (key instanceof Uint8Array) return importJwk({ kty: "oct", k: Buffer.from(key).toString("base64url") });
  if (typeof (key as KeyObject).export === "function" && typeof (key as KeyObject).type === "string") return key as KeyObject;
  return importJwk(key as Jwk);
}

const listOf = (v: string | readonly string[]) => (typeof v === "string" ? [v] : v);
const mediaType = (t: string) => t.toLowerCase().replace(/^application\//, "");

/** Verifies a JWT: its signature against `key`, then its claims. Returns its header and payload, or throws a JwksError. */
export async function verifyJwt(token: string, key: VerificationKey, options: VerifyOptions = {}): Promise<VerifiedJwt> {
  const { algorithms = ASYMMETRIC, clockToleranceS = 0, maxTokenLength = 16_384 } = options;
  /* 1. Shape. */
  if (typeof token !== "string") throw malformed("a JWT is a string");
  if (token.length > maxTokenLength) throw malformed(`the token is over ${maxTokenLength} characters`);
  const parts = token.split(".");
  if (parts.length !== 3) throw malformed("a JWT has three parts");
  const [h, p, s] = parts as [string, string, string];
  if (!h || !p || !s || !B64URL.test(h) || !B64URL.test(p) || !B64URL.test(s)) throw malformed("a JWT's parts are base64url, none empty");
  const header = decodeJson(h, "header") as unknown as JwsHeader;
  const payload = decodeJson(p, "payload") as JwtPayload;

  /* 2. Header. */
  if (typeof header.alg !== "string") throw new JwksError("ERR_JWS_ALGORITHM", "the header has no alg");
  if ((header.alg as string) === "none" || !algorithms.includes(header.alg)) throw new JwksError("ERR_JWS_ALGORITHM", `the algorithm ${JSON.stringify(header.alg)} is not accepted`);
  if (!(header.alg in HASH)) throw new JwksError("ERR_JWS_ALGORITHM", `the algorithm ${header.alg} is not supported`);
  if (header.crit !== undefined) throw new JwksError("ERR_JWS_UNSUPPORTED", "the header has crit: no extension is understood");
  if (header.b64 !== undefined && header.b64 !== true) throw new JwksError("ERR_JWS_UNSUPPORTED", "unencoded payloads (b64: false) are not supported");
  if (header.kid !== undefined && typeof header.kid !== "string") throw malformed("the header's kid is not a string");

  /* 3. Signature. */
  const keys = isKeySet(key) ? await key.getKeys(header) : [keyObjectOf(key)];
  const data = Buffer.from(`${h}.${p}`, "ascii");
  const signature = Buffer.from(s, "base64url");
  let verified = false;
  for (const k of keys) {
    assertKeyFits(k, header.alg);
    if (verifies(header.alg, k, data, signature)) { verified = true; break; }
  }
  if (!verified) throw new JwksError("ERR_JWS_SIGNATURE", "the signature does not verify");

  /* 4. Claims. */
  const now = Math.floor((options.currentDate?.getTime() ?? Date.now()) / 1000);
  for (const claim of ["exp", "nbf", "iat"] as const) {
    if (payload[claim] !== undefined && !(typeof payload[claim] === "number" && Number.isFinite(payload[claim]))) throw claimError(claim, `${claim} is not a number`);
  }
  if (payload.exp !== undefined && payload.exp <= now - clockToleranceS) throw new JwksError("ERR_JWT_EXPIRED", "the token has expired", { claim: "exp" });
  if (payload.nbf !== undefined && payload.nbf > now + clockToleranceS) throw new JwksError("ERR_JWT_NOT_YET_VALID", "the token is not valid yet", { claim: "nbf" });
  if (options.maxTokenAgeS !== undefined) {
    if (payload.iat === undefined) throw claimError("iat", "the token has no iat, which its age needs");
    if (payload.iat > now + clockToleranceS) throw new JwksError("ERR_JWT_NOT_YET_VALID", "the token was issued in the future", { claim: "iat" });
    if (now - payload.iat > options.maxTokenAgeS + clockToleranceS) throw new JwksError("ERR_JWT_EXPIRED", "the token is too old", { claim: "iat" });
  }
  if (options.issuer !== undefined && !listOf(options.issuer).includes(payload.iss as string)) throw claimError("iss", "the token was issued by another issuer");
  if (options.audience !== undefined) {
    const aud = typeof payload.aud === "string" ? [payload.aud] : Array.isArray(payload.aud) ? payload.aud : [];
    if (!listOf(options.audience).some((a) => aud.includes(a))) throw claimError("aud", "the token is for another audience");
  }
  if (options.subject !== undefined && payload.sub !== options.subject) throw claimError("sub", "the token is for another subject");
  if (options.typ !== undefined && (typeof header.typ !== "string" || mediaType(header.typ) !== mediaType(options.typ))) throw claimError("typ", `the token's typ is not ${options.typ}`);
  for (const claim of options.requiredClaims ?? []) if (payload[claim] === undefined) throw claimError(claim, `the token has no ${claim}`);
  return { header, payload };
}
