/*
 * @runsnip/jwks against jose: verifying one JWT against a local key set (kid, signature, exp, iss, aud), per algorithm.
 * Each library verifies the same token N times after a warm-up, in alternating rounds; the median round is reported
 * (verifications per second, and µs per verification). Then each library's load time, in fresh processes.
 *
 *   npm run build && node bench/verify.mjs [--n 20000] [--rounds 5]
 */
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import * as jose from "jose";
import { createLocalJwks, verifyJwt } from "../dist/index.js";

const arg = (name, value) => { const i = process.argv.indexOf(`--${name}`); return i === -1 ? value : Number(process.argv[i + 1]); };
const N = arg("n", 20_000), ROUNDS = arg("rounds", 5), WARM = 2_000;
const now = Math.floor(Date.now() / 1000);
const claims = { iss: "https://issuer.example", aud: "api", sub: "alice", exp: now + 3600 };
const options = { issuer: claims.iss, audience: claims.aud };

async function setup(alg) {
  if (alg === "HS256") {
    const secret = randomBytes(32);
    const token = await new jose.SignJWT(claims).setProtectedHeader({ alg, kid: "k" }).sign(secret);
    return { alg, token, ours: () => verifyJwt(token, secret, { ...options, algorithms: [alg] }), theirs: () => jose.jwtVerify(token, secret, { ...options, algorithms: [alg] }) };
  }
  const { publicKey, privateKey } = await jose.generateKeyPair(alg === "EdDSA" ? "Ed25519" : alg, { extractable: true });
  const jwks = { keys: [{ ...(await jose.exportJWK(publicKey)), kid: "k", alg, use: "sig" }] };
  const token = await new jose.SignJWT(claims).setProtectedHeader({ alg, kid: "k" }).sign(privateKey);
  const ourSet = createLocalJwks(jwks), theirSet = jose.createLocalJWKSet(jwks);
  return { alg, token, ours: () => verifyJwt(token, ourSet, { ...options, algorithms: [alg] }), theirs: () => jose.jwtVerify(token, theirSet, { ...options, algorithms: [alg] }) };
}

async function round(fn) {
  for (let i = 0; i < WARM; i++) await fn();
  const t = process.hrtime.bigint();
  for (let i = 0; i < N; i++) await fn();
  return Number(process.hrtime.bigint() - t) / 1e3 / N;     // µs per verification
}
const median = (xs) => [...xs].sort((a, b) => a - b)[xs.length >> 1];

console.log(`Node ${process.version}, jose ${JSON.parse(execFileSync("npm", ["ls", "jose", "--json"], { encoding: "utf8" })).dependencies.jose.version}; ${N} verifications × ${ROUNDS} rounds, median`);
console.log("| Algorithm | @runsnip/jwks | jose | ratio |\n|---|---|---|---|");
for (const alg of ["RS256", "PS256", "ES256", "EdDSA", "HS256"]) {
  const s = await setup(alg);
  const ours = [], theirs = [];
  for (let r = 0; r < ROUNDS; r++) { ours.push(await round(s.ours)); theirs.push(await round(s.theirs)); }
  const o = median(ours), t = median(theirs);
  console.log(`| ${alg} | ${o.toFixed(1)} µs (${Math.round(1e6 / o)}/s) | ${t.toFixed(1)} µs (${Math.round(1e6 / t)}/s) | ${(t / o).toFixed(2)}× |`);
}

const load = (code) => median(Array.from({ length: 7 }, () => Number(execFileSync(process.execPath, ["--input-type=module", "-e", code], { encoding: "utf8" }))));
const ourLoad = load(`const t = performance.now(); await import(${JSON.stringify(new URL("../dist/index.js", import.meta.url).href)}); console.log(performance.now() - t)`);
const theirLoad = load(`const t = performance.now(); await import("jose"); console.log(performance.now() - t)`);
console.log(`\nload (median of 7 fresh processes): @runsnip/jwks ${ourLoad.toFixed(1)} ms, jose ${theirLoad.toFixed(1)} ms`);
