import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import * as jose from "jose";
import { createAccessTokenVerifier, createRemoteJwks, discover, introspectAccessToken, JwksError, verifyJwt } from "../src/index.ts";

const now = Math.floor(Date.now() / 1000);
const code = async (p: Promise<unknown>) => { try { await p; return "ok"; } catch (e) { return (e as JwksError).code ?? (e as Error).message; } };
const later = (ms: number) => new Promise((r) => setTimeout(r, ms));

/* An authorization server on 127.0.0.1: metadata, a key set it can rotate, introspection; counts what is asked. */
async function authServer() {
  const keys = [await key("k1")];
  const hits: Record<string, number> = {};
  const state = { down: false, issuer: "", metadataIssuer: null as string | null, introspection: { active: true } as Record<string, unknown>, lastAuth: "" };
  const server = http.createServer((req, res) => {
    const url = req.url ?? "";
    hits[url] = (hits[url] ?? 0) + 1;
    if (state.down) return res.writeHead(503).end();
    if (url === "/.well-known/oauth-authorization-server") return res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ issuer: state.metadataIssuer ?? state.issuer, jwks_uri: `${state.issuer}/jwks`, introspection_endpoint: `${state.issuer}/introspect` }));
    if (url === "/jwks") return res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ keys: keys.map((k) => k.jwk) }));
    if (url === "/introspect" && req.method === "POST") { state.lastAuth = req.headers.authorization ?? ""; return res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(state.introspection)); }
    res.writeHead(404).end();
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  state.issuer = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  return { keys, hits, state, close: () => new Promise((r) => server.close(r)) };
}
async function key(kid: string) {
  const { publicKey, privateKey } = await jose.generateKeyPair("ES256", { extractable: true });
  return { kid, privateKey, jwk: { ...(await jose.exportJWK(publicKey)), kid, alg: "ES256", use: "sig" } };
}
const token = (k: { kid: string; privateKey: unknown }, claims: jose.JWTPayload, header: object = {}) =>
  new jose.SignJWT(claims).setProtectedHeader({ alg: "ES256", kid: k.kid, ...header }).sign(k.privateKey as never);

test("a remote key set: one fetch for concurrent verifications, a rotated key fetched after the cooldown, old keys kept when the server fails", async () => {
  const as = await authServer();
  try {
    const jwks = createRemoteJwks(`${as.state.issuer}/jwks`, { cooldownMs: 100, maxAgeMs: 150 });
    const t1 = await token(as.keys[0]!, { exp: now + 60 });
    await Promise.all(Array.from({ length: 20 }, () => verifyJwt(t1, jwks)));
    assert.equal(as.hits["/jwks"], 1);
    /* A key rotated in: unknown until the cooldown has passed since the last fetch. */
    as.keys.push(await key("k2"));
    const t2 = await token(as.keys[1]!, { exp: now + 60 });
    assert.equal(await code(verifyJwt(t2, jwks)), "ERR_JWK_NO_MATCH");
    assert.equal(as.hits["/jwks"], 1);
    await later(120);
    assert.equal(await code(verifyJwt(t2, jwks)), "ok");
    assert.equal(as.hits["/jwks"], 2);
    /* The server down past maxAge: the keys held still verify. */
    as.state.down = true;
    await later(170);
    assert.equal(await code(verifyJwt(t1, jwks)), "ok");
    /* A new key set that cannot be fetched at all. */
    assert.equal(await code(verifyJwt(t1, createRemoteJwks(`${as.state.issuer}/jwks`))), "ERR_JWKS_FETCH");
  } finally { await as.close(); }
  assert.throws(() => createRemoteJwks("http://auth.example.com/jwks"), /https/);
});

test("discovery: RFC 8414 metadata, and an issuer that does not match is refused", async () => {
  const as = await authServer();
  try {
    assert.equal((await discover(as.state.issuer)).jwks_uri, `${as.state.issuer}/jwks`);
    as.state.metadataIssuer = "https://evil.example";
    assert.equal(await code(discover(as.state.issuer)), "ERR_DISCOVERY");
  } finally { await as.close(); }
});

test("access tokens: discovered keys, audience, scopes, and RFC 9068 to the letter with strict", async () => {
  const as = await authServer();
  try {
    const verify = createAccessTokenVerifier({ issuer: as.state.issuer, audience: "https://api.example.com", scopes: ["read"] });
    const k = as.keys[0]!;
    const claims = { iss: as.state.issuer, aud: "https://api.example.com", sub: "alice", client_id: "app", exp: now + 60, iat: now, jti: "1", scope: "read write" };
    const ok = await verify(await token(k, claims));
    assert.deepEqual([ok.subject, ok.clientId, ok.scopes], ["alice", "app", ["read", "write"]]);
    assert.equal(await code(verify(await token(k, { ...claims, scope: "write" }))), "ERR_JWT_CLAIM");
    assert.equal(await code(verify(await token(k, claims), { scopes: ["admin"] })), "ERR_JWT_CLAIM");
    assert.equal(await code(verify(await token(k, { ...claims, aud: "https://other.example.com" }))), "ERR_JWT_CLAIM");
    assert.equal(await code(verify(await token(k, { ...claims, exp: undefined }))), "ERR_JWT_CLAIM");
    assert.equal(await code(verify(await token(k, { ...claims, scope: undefined, scp: ["read"] }))), "ok");
    const strict = createAccessTokenVerifier({ issuer: as.state.issuer, audience: "https://api.example.com", strict: true });
    assert.equal(await code(strict(await token(k, claims))), "ERR_JWT_CLAIM");
    assert.equal(await code(strict(await token(k, claims, { typ: "at+jwt" }))), "ok");
    assert.equal(await code(strict(await token(k, { ...claims, jti: undefined }, { typ: "at+jwt" }))), "ERR_JWT_CLAIM");
    assert.equal(as.hits["/.well-known/oauth-authorization-server"], 2);    // once per verifier
  } finally { await as.close(); }
});

test("introspection: active, credentials, issuer, audience and scopes", async () => {
  const as = await authServer();
  try {
    const options = { endpoint: `${as.state.issuer}/introspect`, clientId: "rs", clientSecret: "s3cret", issuer: as.state.issuer, audience: "api", scopes: ["read"] };
    as.state.introspection = { active: true, iss: as.state.issuer, aud: "api", sub: "bob", scope: "read", exp: now + 60 };
    const ok = await introspectAccessToken("opaque", options);
    assert.equal(ok.subject, "bob");
    assert.equal(as.state.lastAuth, `Basic ${Buffer.from("rs:s3cret").toString("base64")}`);
    as.state.introspection = { active: false };
    assert.equal(await code(introspectAccessToken("opaque", options)), "ERR_JWT_CLAIM");
    as.state.introspection = { active: true, aud: "other", scope: "read" };
    assert.equal(await code(introspectAccessToken("opaque", options)), "ERR_JWT_CLAIM");
    as.state.introspection = { active: true, scope: "write" };
    assert.equal(await code(introspectAccessToken("opaque", options)), "ERR_JWT_CLAIM");
    as.state.introspection = { active: true, scope: "read", exp: now - 3600 };
    assert.equal(await code(introspectAccessToken("opaque", options)), "ERR_JWT_EXPIRED");
    as.state.down = true;
    assert.equal(await code(introspectAccessToken("opaque", options)), "ERR_INTROSPECTION");
  } finally { await as.close(); }
});
