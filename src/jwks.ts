/*
 * Key sets: the keys a token's signature is checked against.
 * - createLocalJwks({ keys }): a JWKS you hold.
 * - createRemoteJwks(url): an authorization server's jwks_uri. Fetched on first use, kept for maxAgeMs (10 min), fetched
 *   again on an unknown kid (a key rotated in) at most every cooldownMs (30 s). One fetch at a time: concurrent
 *   verifications wait for the same one. A failed fetch keeps the keys already held.
 * A key set gives the keys that fit a token's header: its kid when it names one, and always the algorithm (a key
 * verifies only the algorithms of its type, and its own alg when it states one).
 */
import type { KeyObject } from "node:crypto";
import { JwksError } from "./errors.ts";
import { type Algorithm, type Jwk, algorithmsOf, importJwk, isSigningKey } from "./jwk.ts";

export interface JwsHeader {
  alg: Algorithm;
  kid?: string;
  typ?: string;
  [member: string]: unknown;
}

/** Anything that gives the keys a header may be verified with. */
export interface KeySet {
  getKeys(header: JwsHeader): Promise<KeyObject[]>;
}

export interface Jwks {
  keys: Jwk[];
}

interface Entry {
  jwk: Jwk;
  algorithms: Algorithm[];
  key: KeyObject | null;          // imported on first use
  invalid: boolean;
}

function entriesOf(jwks: unknown): Entry[] {
  if (!jwks || typeof jwks !== "object" || !Array.isArray((jwks as Jwks).keys)) throw new JwksError("ERR_JWKS_FETCH", "a JWKS is an object with a keys array");
  return (jwks as Jwks).keys.filter((jwk) => jwk && typeof jwk === "object" && isSigningKey(jwk)).map((jwk) => ({ jwk, algorithms: algorithmsOf(jwk), key: null, invalid: false }));
}

function select(entries: Entry[], header: JwsHeader): KeyObject[] {
  const keys: KeyObject[] = [];
  for (const entry of entries) {
    if (!entry.algorithms.includes(header.alg)) continue;
    if (header.kid !== undefined && entry.jwk.kid !== header.kid) continue;
    if (entry.invalid) continue;
    if (!entry.key) {
      try { entry.key = importJwk(entry.jwk); } catch { entry.invalid = true; continue; }
    }
    keys.push(entry.key);
  }
  return keys;
}

const noMatch = (header: JwsHeader) => new JwksError("ERR_JWK_NO_MATCH", `no key of the set verifies ${header.alg}${header.kid !== undefined ? ` with kid ${JSON.stringify(header.kid)}` : ""}`);

/** A key set you hold. */
export function createLocalJwks(jwks: Jwks): KeySet {
  const entries = entriesOf(jwks);
  return {
    async getKeys(header) {
      const keys = select(entries, header);
      if (!keys.length) throw noMatch(header);
      return keys;
    },
  };
}

export interface RemoteJwksOptions {
  /** How long the keys are used before they are fetched again (default 600 000 ms). */
  maxAgeMs?: number;
  /** The least time between two fetches for an unknown kid (default 30 000 ms). */
  cooldownMs?: number;
  /** A fetch that takes longer fails (default 5 000 ms). */
  timeoutMs?: number;
  /** A larger key set is refused (default 1 MiB). */
  maxBytes?: number;
  headers?: Record<string, string>;
  fetch?: typeof fetch;
}

export interface RemoteJwks extends KeySet {
  /** Fetches the key set now. */
  refresh(): Promise<void>;
  /** The key set held, or null before the first fetch. */
  jwks(): Jwks | null;
}

/** An authorization server's key set, at its jwks_uri. */
export function createRemoteJwks(url: string | URL, options: RemoteJwksOptions = {}): RemoteJwks {
  const uri = new URL(url);
  if (uri.protocol !== "https:" && !["localhost", "127.0.0.1", "[::1]"].includes(uri.hostname)) throw new JwksError("ERR_JWKS_FETCH", `a key set is fetched over https, not ${uri.protocol}`);
  const { maxAgeMs = 600_000, cooldownMs = 30_000, timeoutMs = 5_000, maxBytes = 1 << 20, headers = {}, fetch: fetchImpl = fetch } = options;
  let held: { jwks: Jwks; entries: Entry[]; at: number } | null = null;
  let lastAttempt = 0;
  let inflight: Promise<void> | null = null;

  async function load(): Promise<void> {
    lastAttempt = Date.now();
    let res: Response;
    try {
      res = await fetchImpl(uri, { headers: { accept: "application/jwk-set+json, application/json", ...headers }, signal: AbortSignal.timeout(timeoutMs), redirect: "error" });
    } catch (cause) {
      throw new JwksError("ERR_JWKS_FETCH", `the key set at ${uri} could not be fetched: ${(cause as Error).message}`, { cause });
    }
    if (!res.ok) throw new JwksError("ERR_JWKS_FETCH", `the key set at ${uri} answered ${res.status}`);
    const text = await res.text();
    if (Buffer.byteLength(text) > maxBytes) throw new JwksError("ERR_JWKS_FETCH", `the key set at ${uri} is over ${maxBytes} bytes`);
    let jwks: unknown;
    try { jwks = JSON.parse(text); } catch (cause) { throw new JwksError("ERR_JWKS_FETCH", `the key set at ${uri} is not JSON`, { cause }); }
    held = { jwks: jwks as Jwks, entries: entriesOf(jwks), at: Date.now() };
  }
  const refresh = (): Promise<void> => (inflight ??= load().finally(() => { inflight = null; }));

  return {
    refresh,
    jwks: () => held?.jwks ?? null,
    async getKeys(header) {
      if (!held) await refresh();
      else if (Date.now() - held.at > maxAgeMs) {
        /* Old keys: fetched again; a failure keeps them. */
        try { await refresh(); } catch { /* held as they were */ }
      }
      let keys = select(held!.entries, header);
      if (!keys.length && Date.now() - lastAttempt >= cooldownMs) {
        /* A key rotated in since the last fetch. */
        try { await refresh(); } catch { /* held as they were */ }
        keys = select(held!.entries, header);
      }
      if (!keys.length) throw noMatch(header);
      return keys;
    },
  };
}
