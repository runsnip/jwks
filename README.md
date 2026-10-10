# @runsnip/jwks

Verify JWTs and OAuth access tokens against JSON Web Key Sets, with `node:crypto` alone: no dependency.

```sh
npm install @runsnip/jwks
```

```js
import { createAccessTokenVerifier } from "@runsnip/jwks";

const verify = createAccessTokenVerifier({
  issuer: "https://auth.example.com",
  audience: "https://api.example.com",      // this resource server
  scopes: ["read"],                          // every token needs them
});

const { subject, scopes, payload } = await verify(token);              // or throws a JwksError
await verify(token, { scopes: ["orders:write"] });                    // scopes this call needs beyond them
```

The issuer's key set is found from its metadata (RFC 8414, else OpenID Connect discovery), fetched once, kept, and
fetched again when a key rotates in.

## API

| | |
|---|---|
| `verifyJwt(token, key, options)` | A JWT: signature, then claims. `key` is a key set, a `KeyObject`, a JWK, or a secret (HMAC) |
| `createRemoteJwks(url, options)` | A key set at a `jwks_uri` |
| `createLocalJwks({ keys })` | A key set you hold |
| `createAccessTokenVerifier(options)` | JWT access tokens of one issuer for one resource server; `strict: true` for RFC 9068 to the letter |
| `discover(issuer)` | The authorization server's metadata |
| `introspect(token, { endpoint, clientId, clientSecret })` | RFC 7662 |
| `introspectAccessToken(token, options)` | `introspect`, then the checks an access token gets |
| `JwksError` | Every refusal, with a `code` (below) and, for a claim, `claim` |

### `verifyJwt(token, key, options)`

```js
import { createRemoteJwks, verifyJwt } from "@runsnip/jwks";

const keys = createRemoteJwks("https://auth.example.com/.well-known/jwks.json");
const { header, payload } = await verifyJwt(token, keys, {
  issuer: "https://auth.example.com",
  audience: "api",
  algorithms: ["RS256", "ES256"],           // default: every asymmetric one; an HMAC only when named
  clockToleranceS: 60,                       // default 0
});
```

| Option | | |
|---|---|---|
| `algorithms` | `RS256` `RS384` `RS512` `PS256` `PS384` `PS512` `ES256` `ES384` `ES512` `EdDSA` `Ed25519` `HS256` `HS384` `HS512` | Default: the asymmetric ones |
| `issuer`, `audience` | a string or a list | `iss` must be one; `aud` must hold one |
| `subject` | a string | `sub` must be it |
| `typ` | `"at+jwt"`… | The header's `typ`, `application/` and case aside |
| `clockToleranceS` | seconds | Leeway on `exp`, `nbf`, `iat` |
| `maxTokenAgeS` | seconds | The most since `iat` (then required) |
| `requiredClaims` | names | Claims that must be present |
| `currentDate` | a `Date` | Instead of now |
| `maxTokenLength` | characters | Default 16 384 |

### `createRemoteJwks(url, options)`

Fetched on first use and kept `maxAgeMs` (10 minutes); fetched again for an unknown `kid` at most every `cooldownMs`
(30 s); one fetch at a time, which concurrent verifications share; a failed fetch keeps the keys held. Over https
(`localhost` aside), no redirect, `timeoutMs` 5 s, `maxBytes` 1 MiB. `refresh()` fetches now; `jwks()` is what is
held.

## What is refused, and why

| Code | |
|---|---|
| `ERR_JWT_MALFORMED` | Not three parts of strict base64url (no padding, none empty), a header or payload that is not a JSON object, or over the size limit |
| `ERR_JWS_ALGORITHM` | An `alg` not in `algorithms`. `none` never is |
| `ERR_JWS_UNSUPPORTED` | A `crit` header (no extension is understood), or `b64: false` |
| `ERR_JWK_NO_MATCH` | No key of the set fits the header: its `kid`, and the algorithm |
| `ERR_JWK_INVALID` | A key that cannot verify the algorithm (below), or a JWK that cannot be read |
| `ERR_JWS_SIGNATURE` | The signature does not verify |
| `ERR_JWT_EXPIRED`, `ERR_JWT_NOT_YET_VALID` | `exp` passed; `nbf` (or `iat`) in the future |
| `ERR_JWT_CLAIM` | `iss`, `aud`, `sub`, `typ`, a required claim, a scope, a claim of the wrong type |
| `ERR_JWKS_FETCH`, `ERR_DISCOVERY`, `ERR_INTROSPECTION` | The network, or an answer that is not what it must be |

**A key verifies only its own algorithms.** An RSA key verifies `RS*` and `PS*`, never an HMAC: the classic attack
that signs an `HS256` token with a server's public key as the secret is refused by the key's type, whatever
`algorithms` holds. An EC key verifies its curve's `ES*` only; an OKP key `EdDSA`; a secret `HS*`, of 32, 48 or 64
bytes or more. RSA keys are 2048 bits or more. A JWK's own `alg`, `use` and `key_ops` are honoured. A key set's key
that holds a private part (`d`) is never used.

**Stricter than jose on purpose:** a signature with base64 padding (`=`) is refused, as RFC 7515's compact form has
none. The tests check every other verdict against jose's (`tests/verify.test.ts`, 156 tokens, every algorithm).

## Speed

Node 24.16, Apple M1, 2026-10-10. One token verified against a local key set (kid, signature, `exp`, `iss`, `aud`),
20 000 times after a warm-up, median of 5 rounds alternating with jose 6.2.12 (`node bench/verify.mjs`):

| Algorithm | @runsnip/jwks | jose | |
|---|---|---|---|
| RS256 | 21.8 µs | 44.0 µs | 2.0× |
| PS256 | 23.3 µs | 52.1 µs | 2.2× |
| ES256 | 70.2 µs | 89.0 µs | 1.27× |
| EdDSA | 96.0 µs | 117.9 µs | 1.23× |
| HS256 | 5.0 µs | 29.6 µs | 5.9× |

Loading it: 4.6 ms, against 13.6 ms (median of 7 fresh processes).

**Where the time goes:** OpenSSL's signature check itself, `crypto.verify` alone, is 18.1 µs for RS256, 60.9 µs for
ES256 and 91.0 µs for EdDSA on the same machine: 83 to 95% of a verification. What this package adds (parsing, the key
lookup, the claims) is 4 to 9 µs. A faster verification needs a faster signature check, below this package.

## Requirements

Node.js 20.19 or later (an ES module, which `require()` loads there too). MIT.
