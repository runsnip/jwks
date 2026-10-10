import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign as nodeSign } from "node:crypto";
import * as jose from "jose";
import { type Algorithm, createLocalJwks, JwksError, verifyJwt } from "../src/index.ts";

const ALGS: Algorithm[] = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA", "HS256", "HS384", "HS512"];
const now = Math.floor(Date.now() / 1000);

/* One key pair per algorithm, the JWKS a server would publish, and a token signed by jose. */
async function setup(alg: Algorithm) {
  if (alg.startsWith("HS")) {
    const secret = randomBytes(64);
    return { alg, verifyKey: secret, signKey: secret, jwks: { keys: [{ kty: "oct", kid: "k", k: secret.toString("base64url") }] } };
  }
  const { publicKey, privateKey } = await jose.generateKeyPair(alg === "EdDSA" ? "Ed25519" : alg, { extractable: true });
  const jwk = { ...(await jose.exportJWK(publicKey)), kid: "k", alg, use: "sig" };
  return { alg, verifyKey: publicKey, signKey: privateKey, jwks: { keys: [jwk] } };
}
const sign = (s: Awaited<ReturnType<typeof setup>>, claims: jose.JWTPayload, header: Partial<jose.JWTHeaderParameters> = {}) =>
  new jose.SignJWT(claims).setProtectedHeader({ alg: s.alg, kid: "k", ...header }).sign(s.signKey as never);
const code = async (p: Promise<unknown>) => { try { await p; return "ok"; } catch (e) { return (e as JwksError).code ?? (e as Error).message; } };

test("every algorithm: a token jose signs verifies, against a key set and against the key", async () => {
  for (const alg of ALGS) {
    const s = await setup(alg);
    const token = await sign(s, { iss: "https://issuer.example", aud: "api", sub: "alice", exp: now + 60 });
    const options = { algorithms: [alg], issuer: "https://issuer.example", audience: "api" };
    const fromSet = await verifyJwt(token, createLocalJwks(s.jwks as never), options);
    assert.equal(fromSet.payload.sub, "alice", alg);
    assert.equal(fromSet.header.alg, alg);
    const key = alg.startsWith("HS") ? (s.verifyKey as Uint8Array) : s.jwks.keys[0];
    assert.equal((await verifyJwt(token, key as never, options)).payload.sub, "alice", alg);
  }
});

test("differential against jose: the same verdict on tokens tampered every way", async () => {
  let compared = 0;
  for (const alg of ALGS) {
    const s = await setup(alg);
    const good = await sign(s, { iss: "i", aud: "a", exp: now + 60, nbf: now - 10 });
    const [h, p, sig] = good.split(".") as [string, string, string];
    const variants = [
      good,
      `${h}.${p}.${sig.slice(0, -2)}${sig.slice(-2) === "AA" ? "AB" : "AA"}`,            // signature changed
      `${h}.${Buffer.from(JSON.stringify({ iss: "i", aud: "a", exp: now + 999 })).toString("base64url")}.${sig}`,  // payload swapped
      `${h}.${p}.`,                                                                    // no signature
      `${h}.${p}`,                                                                     // two parts
      `${h}.${p}.${sig}=`,                                                             // padding
      await sign(s, { iss: "i", aud: "a", exp: now - 120 }),                           // expired
      await sign(s, { iss: "i", aud: "a", exp: now + 60, nbf: now + 600 }),            // not yet valid
      await sign(s, { iss: "other", aud: "a", exp: now + 60 }),                        // another issuer
      await sign(s, { iss: "i", aud: ["x", "a"], exp: now + 60 }),                     // audience in a list
      await sign(s, { iss: "i", aud: "b", exp: now + 60 }),                            // another audience
      await sign(s, { iss: "i", aud: "a", exp: "soon" as never }),                     // exp not a number
    ];
    /* Where this package is stricter than jose, on purpose: RFC 7515's compact form has no base64 padding (jose
       decodes past it). Anywhere else the verdicts must be the same; this package must never accept what jose refuses. */
    const STRICTER = new Set([5]);
    for (const [i, token] of variants.entries()) {
      const ours = await code(verifyJwt(token, createLocalJwks(s.jwks as never), { algorithms: [alg], issuer: "i", audience: "a" }));
      /* jose's key sets hold no secrets: an HMAC is checked with the secret itself. */
      const against = alg.startsWith("HS") ? (s.verifyKey as Uint8Array) : jose.createLocalJWKSet(s.jwks as never);
      const theirs = await code(jose.jwtVerify(token, against as never, { algorithms: [alg], issuer: "i", audience: "a" }));
      const why = `${alg} variant ${i}: ours ${ours}, jose ${theirs}`;
      if (STRICTER.has(i)) assert.notEqual(ours, "ok", why);
      else assert.equal(ours === "ok", theirs === "ok", why);
      compared++;
    }
  }
  assert.equal(compared, ALGS.length * 12);
});

test("algorithm attacks: none, an algorithm not accepted, an HMAC with a public key, crit, b64", async () => {
  const s = await setup("RS256");
  const keys = createLocalJwks(s.jwks as never);
  const enc = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const body = enc({ exp: now + 60 });
  assert.equal(await code(verifyJwt(`${enc({ alg: "none" })}.${body}.x`, keys, { algorithms: ["RS256"] })), "ERR_JWS_ALGORITHM");
  assert.equal(await code(verifyJwt(`${enc({ alg: "none" })}.${body}.x`, keys, { algorithms: ["none" as never] })), "ERR_JWS_ALGORITHM");
  assert.equal(await code(verifyJwt(await sign(s, { exp: now + 60 }), keys, { algorithms: ["ES256"] })), "ERR_JWS_ALGORITHM");
  /* The classic confusion: the RSA public key's bytes as an HMAC secret. Refused, by key type, whatever the list says. */
  const pem = createPublicKey({ key: s.jwks.keys[0] as never, format: "jwk" }).export({ type: "spki", format: "pem" });
  const head = enc({ alg: "HS256", kid: "k" });
  const forged = `${head}.${body}.${createHmac("sha256", pem).update(`${head}.${body}`).digest("base64url")}`;
  assert.equal(await code(verifyJwt(forged, keys, { algorithms: ["RS256", "HS256"] })), "ERR_JWK_NO_MATCH");
  assert.equal(await code(verifyJwt(forged, s.jwks.keys[0] as never, { algorithms: ["HS256"] })), "ERR_JWK_INVALID");
  /* Headers jose will not sign: built and signed here, with the key, so only the header can be refused. */
  const priv = await jose.exportJWK(s.signKey as never);
  const signed = (header: object) => { const hh = enc({ alg: "RS256", kid: "k", ...header }); return `${hh}.${body}.${nodeSign("sha256", Buffer.from(`${hh}.${body}`), createPrivateKey({ key: priv as never, format: "jwk" })).toString("base64url")}`; };
  assert.equal(await code(verifyJwt(signed({}), keys)), "ok");
  assert.equal(await code(verifyJwt(signed({ crit: ["exp"], exp: 1 }), keys)), "ERR_JWS_UNSUPPORTED");
  assert.equal(await code(verifyJwt(signed({ b64: false }), keys)), "ERR_JWS_UNSUPPORTED");
});

test("keys: RSA under 2048 bits, an EC key of another curve, a DER ECDSA signature, a key set's private keys and encryption keys", async () => {
  const small = generateKeyPairSync("rsa", { modulusLength: 1024 });
  const enc = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const head = enc({ alg: "RS256" }), body = enc({ exp: now + 60 });
  const weak = `${head}.${body}.${nodeSign("sha256", Buffer.from(`${head}.${body}`), small.privateKey).toString("base64url")}`;
  assert.equal(await code(verifyJwt(weak, small.publicKey)), "ERR_JWK_INVALID");

  /* A P-384 key, named ES256 in the header: refused for its curve. */
  const p384 = generateKeyPairSync("ec", { namedCurve: "secp384r1" });
  const h256 = enc({ alg: "ES256" });
  const mislabelled = `${h256}.${body}.${nodeSign("sha256", Buffer.from(`${h256}.${body}`), { key: p384.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url")}`;
  assert.equal(await code(verifyJwt(mislabelled, p384.publicKey)), "ERR_JWK_INVALID");

  const ec = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const eh = enc({ alg: "ES256" });
  const der = nodeSign("sha256", Buffer.from(`${eh}.${body}`), ec.privateKey).toString("base64url");     // DER, not JWS's r||s
  assert.equal(await code(verifyJwt(`${eh}.${body}.${der}`, ec.publicKey)), "ERR_JWS_SIGNATURE");
  const p1363 = nodeSign("sha256", Buffer.from(`${eh}.${body}`), { key: ec.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
  assert.equal(await code(verifyJwt(`${eh}.${body}.${p1363}`, ec.publicKey)), "ok");

  /* A key set publishing a private key (d), or a key for encryption: never used to verify. */
  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const priv = { ...rsa.privateKey.export({ format: "jwk" }), kid: "p" };
  const rh = enc({ alg: "RS256", kid: "p" });
  const token = `${rh}.${body}.${nodeSign("sha256", Buffer.from(`${rh}.${body}`), rsa.privateKey).toString("base64url")}`;
  assert.equal(await code(verifyJwt(token, createLocalJwks({ keys: [priv as never] }))), "ERR_JWK_NO_MATCH");
  const pub = { ...rsa.publicKey.export({ format: "jwk" }), kid: "p" };
  assert.equal(await code(verifyJwt(token, createLocalJwks({ keys: [{ ...pub, use: "enc" } as never] }))), "ERR_JWK_NO_MATCH");
  assert.equal(await code(verifyJwt(token, createLocalJwks({ keys: [pub as never] }))), "ok");
});

test("claims: tolerance, maxTokenAgeS, sub, typ, required claims, the size limit", async () => {
  const s = await setup("ES256");
  const keys = createLocalJwks(s.jwks as never);
  assert.equal(await code(verifyJwt(await sign(s, { exp: now - 30 }), keys)), "ERR_JWT_EXPIRED");
  assert.equal(await code(verifyJwt(await sign(s, { exp: now - 30 }), keys, { clockToleranceS: 60 })), "ok");
  assert.equal(await code(verifyJwt(await sign(s, { iat: now - 100 }), keys, { maxTokenAgeS: 50 })), "ERR_JWT_EXPIRED");
  assert.equal(await code(verifyJwt(await sign(s, {}), keys, { maxTokenAgeS: 50 })), "ERR_JWT_CLAIM");
  assert.equal(await code(verifyJwt(await sign(s, { sub: "bob" }), keys, { subject: "alice" })), "ERR_JWT_CLAIM");
  assert.equal(await code(verifyJwt(await sign(s, {}, { typ: "application/AT+JWT" }), keys, { typ: "at+jwt" })), "ok");
  assert.equal(await code(verifyJwt(await sign(s, {}, { typ: "JWT" }), keys, { typ: "at+jwt" })), "ERR_JWT_CLAIM");
  assert.equal(await code(verifyJwt(await sign(s, {}), keys, { requiredClaims: ["jti"] })), "ERR_JWT_CLAIM");
  assert.equal(await code(verifyJwt(await sign(s, { pad: "x".repeat(20_000) }), keys)), "ERR_JWT_MALFORMED");
  try { await verifyJwt(await sign(s, { aud: "x" }), keys, { audience: "y" }); } catch (e) { assert.equal((e as JwksError).claim, "aud"); }
});
