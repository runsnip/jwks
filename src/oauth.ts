/*
 * OAuth 2.x on the resource server's side:
 * - discover(issuer): the authorization server's metadata (RFC 8414, then OpenID Connect Discovery), whose issuer must
 *   be the one asked for (RFC 8414 §3.3);
 * - createAccessTokenVerifier({ issuer, audience }): JWT access tokens, checked against the issuer's key set (its
 *   jwks_uri, discovered once), with the claims RFC 9068 asks of one (strict) or the ones every JWT access token has;
 *   scopes from scope (a space-separated string) or scp;
 * - introspect(token, { endpoint }): RFC 7662, and introspectAccessToken, the same checks on its answer.
 */
import { JwksError } from "./errors.ts";
import { type Algorithm, ASYMMETRIC } from "./jwk.ts";
import { type KeySet, type JwsHeader, createRemoteJwks, type RemoteJwksOptions } from "./jwks.ts";
import { type JwtPayload, verifyJwt } from "./verify.ts";

export interface AuthorizationServerMetadata {
  issuer: string;
  jwks_uri?: string;
  introspection_endpoint?: string;
  token_endpoint?: string;
  authorization_endpoint?: string;
  scopes_supported?: string[];
  [member: string]: unknown;
}

export interface FetchOptions {
  fetch?: typeof fetch;
  /** A request that takes longer fails (default 5 000 ms). */
  timeoutMs?: number;
}

const local = (u: URL) => ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);

/** The authorization server's metadata: RFC 8414's well-known URL, then OpenID Connect's. */
export async function discover(issuer: string, options: FetchOptions = {}): Promise<AuthorizationServerMetadata> {
  const { fetch: fetchImpl = fetch, timeoutMs = 5_000 } = options;
  let at: URL;
  try { at = new URL(issuer); } catch { throw new JwksError("ERR_DISCOVERY", `the issuer ${JSON.stringify(issuer)} is not a URL`); }
  if (at.protocol !== "https:" && !local(at)) throw new JwksError("ERR_DISCOVERY", "an issuer is an https URL");
  const path = at.pathname === "/" ? "" : at.pathname.replace(/\/$/, "");
  const urls = [`${at.origin}/.well-known/oauth-authorization-server${path}`, `${at.origin}${path}/.well-known/openid-configuration`];
  const failures: string[] = [];
  for (const url of urls) {
    let res: Response;
    try { res = await fetchImpl(url, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(timeoutMs), redirect: "error" }); }
    catch (error) { failures.push(`${url}: ${(error as Error).message}`); continue; }
    if (!res.ok) { failures.push(`${url}: ${res.status}`); continue; }
    let meta: AuthorizationServerMetadata;
    try { meta = await res.json() as AuthorizationServerMetadata; } catch { failures.push(`${url}: not JSON`); continue; }
    if (meta.issuer !== issuer) throw new JwksError("ERR_DISCOVERY", `the metadata at ${url} names the issuer ${JSON.stringify(meta.issuer)}, not ${JSON.stringify(issuer)}`);
    return meta;
  }
  throw new JwksError("ERR_DISCOVERY", `no metadata for ${issuer} (${failures.join("; ")})`);
}

export interface VerifiedAccessToken {
  header: JwsHeader | null;
  payload: JwtPayload;
  /** From scope or scp. */
  scopes: string[];
  subject: string | null;
  clientId: string | null;
}

/** The scopes a token or an introspection answer grants: scope (space-separated) or scp (a list, or a string). */
export function scopesOf(claims: Record<string, unknown>): string[] {
  if (typeof claims.scope === "string") return claims.scope.split(" ").filter(Boolean);
  if (Array.isArray(claims.scp)) return claims.scp.filter((s): s is string => typeof s === "string");
  if (typeof claims.scp === "string") return claims.scp.split(" ").filter(Boolean);
  return [];
}

function holdScopes(scopes: string[], needed: readonly string[] | undefined): void {
  const missing = (needed ?? []).filter((s) => !scopes.includes(s));
  if (missing.length) throw new JwksError("ERR_JWT_CLAIM", `the token lacks the scopes ${missing.join(", ")}`, { claim: "scope" });
}

const verified = (header: JwsHeader | null, payload: JwtPayload): VerifiedAccessToken => ({
  header, payload, scopes: scopesOf(payload),
  subject: typeof payload.sub === "string" ? payload.sub : null,
  clientId: typeof payload.client_id === "string" ? payload.client_id : typeof payload.azp === "string" ? payload.azp : null,
});

export interface AccessTokenVerifierOptions extends FetchOptions {
  issuer: string;
  /** What the token's aud must hold: the resource server's identifier (its URL). */
  audience: string | readonly string[];
  /** The issuer's keys (default: its jwks_uri, discovered on first use). */
  keys?: KeySet;
  /** Its jwks_uri, when discovery is not wanted. */
  jwksUri?: string;
  algorithms?: readonly Algorithm[];
  /** Scopes every token needs. */
  scopes?: readonly string[];
  /** RFC 9068 to the letter: typ at+jwt, and sub, client_id, iat and jti required (default false: iss, aud, exp). */
  strict?: boolean;
  /** Seconds of leeway on exp, nbf and iat (default 60). */
  clockToleranceS?: number;
  jwks?: RemoteJwksOptions;
}

export interface AccessTokenVerifier {
  /** Verifies a JWT access token; `scopes` are needed beyond the verifier's own. */
  (token: string, options?: { scopes?: readonly string[] }): Promise<VerifiedAccessToken>;
}

/** A verifier of JWT access tokens from one issuer, for one resource server. */
export function createAccessTokenVerifier(options: AccessTokenVerifierOptions): AccessTokenVerifier {
  const { issuer, audience, algorithms = ASYMMETRIC, strict = false, clockToleranceS = 60 } = options;
  if (!audience || (Array.isArray(audience) && !audience.length)) throw new JwksError("ERR_JWT_CLAIM", "an access token verifier needs its audience: the resource server's identifier", { claim: "aud" });
  let keys: KeySet | null = options.keys ?? (options.jwksUri ? createRemoteJwks(options.jwksUri, { fetch: options.fetch, ...options.jwks }) : null);
  let discovering: Promise<KeySet> | null = null;
  const keySet = async (): Promise<KeySet> => {
    if (keys) return keys;
    discovering ??= discover(issuer, options).then((meta) => {
      if (!meta.jwks_uri) throw new JwksError("ERR_DISCOVERY", `the issuer ${issuer} publishes no jwks_uri`);
      return (keys = createRemoteJwks(meta.jwks_uri, { fetch: options.fetch, ...options.jwks }));
    }).finally(() => { discovering = null; });
    return discovering;
  };
  return async (token, call = {}) => {
    const { header, payload } = await verifyJwt(token, await keySet(), {
      algorithms, issuer, audience, clockToleranceS,
      ...(strict ? { typ: "at+jwt", requiredClaims: ["iss", "exp", "aud", "sub", "client_id", "iat", "jti"] } : { requiredClaims: ["iss", "exp", "aud"] }),
    });
    const result = verified(header, payload);
    holdScopes(result.scopes, options.scopes);
    holdScopes(result.scopes, call.scopes);
    return result;
  };
}

export interface IntrospectionOptions extends FetchOptions {
  /** The authorization server's introspection endpoint. */
  endpoint: string;
  /** The resource server's credentials at the authorization server. */
  clientId?: string;
  clientSecret?: string;
  /** How the credentials are sent (default "basic": HTTP Basic, RFC 7662 §2.1). */
  clientAuth?: "basic" | "post";
}

/** RFC 7662: what the authorization server says of a token. */
export async function introspect(token: string, options: IntrospectionOptions): Promise<Record<string, unknown> & { active: boolean }> {
  const { fetch: fetchImpl = fetch, timeoutMs = 5_000, clientAuth = "basic" } = options;
  const endpoint = new URL(options.endpoint);
  if (endpoint.protocol !== "https:" && !local(endpoint)) throw new JwksError("ERR_INTROSPECTION", "an introspection endpoint is an https URL");
  const body = new URLSearchParams({ token, token_type_hint: "access_token" });
  const headers: Record<string, string> = { "content-type": "application/x-www-form-urlencoded", accept: "application/json" };
  if (options.clientId !== undefined) {
    if (clientAuth === "basic") headers.authorization = `Basic ${Buffer.from(`${encodeURIComponent(options.clientId)}:${encodeURIComponent(options.clientSecret ?? "")}`).toString("base64")}`;
    else { body.set("client_id", options.clientId); if (options.clientSecret !== undefined) body.set("client_secret", options.clientSecret); }
  }
  let res: Response;
  try { res = await fetchImpl(endpoint, { method: "POST", headers, body, signal: AbortSignal.timeout(timeoutMs), redirect: "error" }); }
  catch (cause) { throw new JwksError("ERR_INTROSPECTION", `the introspection endpoint could not be reached: ${(cause as Error).message}`, { cause }); }
  if (!res.ok) throw new JwksError("ERR_INTROSPECTION", `the introspection endpoint answered ${res.status}`);
  let answer: unknown;
  try { answer = await res.json(); } catch (cause) { throw new JwksError("ERR_INTROSPECTION", "the introspection endpoint did not answer JSON", { cause }); }
  if (!answer || typeof answer !== "object" || typeof (answer as { active?: unknown }).active !== "boolean") throw new JwksError("ERR_INTROSPECTION", "the introspection answer has no active");
  return answer as Record<string, unknown> & { active: boolean };
}

/** introspect, then the checks a JWT access token gets: active, iss, aud, exp, nbf and scopes. */
export async function introspectAccessToken(token: string, options: IntrospectionOptions & { issuer?: string; audience?: string | readonly string[]; scopes?: readonly string[]; clockToleranceS?: number; currentDate?: Date }): Promise<VerifiedAccessToken> {
  const answer = await introspect(token, options);
  if (!answer.active) throw new JwksError("ERR_JWT_CLAIM", "the token is not active", { claim: "active" });
  const now = Math.floor((options.currentDate?.getTime() ?? Date.now()) / 1000), tolerance = options.clockToleranceS ?? 60;
  if (options.issuer !== undefined && answer.iss !== undefined && answer.iss !== options.issuer) throw new JwksError("ERR_JWT_CLAIM", "the token was issued by another issuer", { claim: "iss" });
  if (options.audience !== undefined && answer.aud !== undefined) {
    const aud = typeof answer.aud === "string" ? [answer.aud] : Array.isArray(answer.aud) ? answer.aud : [];
    const wanted = typeof options.audience === "string" ? [options.audience] : options.audience;
    if (!wanted.some((a) => aud.includes(a))) throw new JwksError("ERR_JWT_CLAIM", "the token is for another audience", { claim: "aud" });
  }
  if (typeof answer.exp === "number" && answer.exp <= now - tolerance) throw new JwksError("ERR_JWT_EXPIRED", "the token has expired", { claim: "exp" });
  if (typeof answer.nbf === "number" && answer.nbf > now + tolerance) throw new JwksError("ERR_JWT_NOT_YET_VALID", "the token is not valid yet", { claim: "nbf" });
  const result = verified(null, answer as JwtPayload);
  holdScopes(result.scopes, options.scopes);
  return result;
}
