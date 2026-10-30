/*
 * Strict Ed25519 (RFC 8032 §5.1.7 with the cofactor cases closed): the checks platforms leave out. OpenSSL (node:crypto)
 * and WebCrypto take a public key or an R of small order — the identity key with R the identity and S = 0 verifies
 * every message — so these run before the platform's verify: A and R canonical (y < p) and not of small order,
 * S < L. The same rules as @runsnip/collab's (SPEC rev 4.2) and ed25519-dalek's verify_strict.
 */

/* y encodings (sign bit cleared) of the eight points of small order, canonical or not: 0, 1, p − 1, p, p + 1 and the
 * two of order 8. */
const SMALL_ORDER = [
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
].map((h) => Buffer.from(h, "hex"));
/* The group order L = 2^252 + 27742317777372353535851937790883648493, little-endian. */
const L = Buffer.from("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010", "hex");

/** Whether a 32-byte point encoding is one strict verification refuses: of small order, or y not below 2^255 − 19. */
export function weakEd25519Point(point: Uint8Array): boolean {
  if (point.length !== 32) return true;
  const y = Buffer.from(point);
  y[31]! &= 0x7f;
  if (SMALL_ORDER.some((s) => s.equals(y))) return true;
  if (y[31] !== 0x7f || y[0]! < 0xed) return false;
  for (let i = 1; i < 31; i++) if (y[i] !== 0xff) return false;
  return true;
}

/** Whether the public key `publicKey` (32 bytes) and the 64-byte `signature` pass the strict checks (the platform's
 * verify is still needed for the equation itself). */
export function strictEd25519(publicKey: Uint8Array, signature: Uint8Array): boolean {
  if (signature.length !== 64 || weakEd25519Point(publicKey) || weakEd25519Point(signature.subarray(0, 32))) return false;
  for (let i = 31; i >= 0; i--) if (signature[32 + i] !== L[i]) return signature[32 + i]! < L[i]!;
  return false;
}
