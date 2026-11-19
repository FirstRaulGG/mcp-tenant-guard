// A small OAuth 2.1 authorization server for public MCP clients.
//
// Public clients only: no client secrets, PKCE (S256) on every flow, one resource. Tokens are
// opaque and stored as hashes, like personal tokens, so they are revoked by deleting nothing and
// checked by the same code path.
//
// The part this file does NOT do is know who is signed in. `approveAuthorization` must be called by
// the host application from behind its own session, after a person looked at a consent screen.

import type { ActorKind } from "../core/actor.js";
import { mixesReadAndWrite, parseScopes, scopesOfNature } from "../core/scopes.js";
import { candidateHashes, classifyToken, generateToken, hashToken, randomSecret, tokenUsability } from "../core/tokens.js";
import type { Guard, OAuthConfig } from "../guard/guard.js";
import type { AuthorizationCode, OAuthClient, OAuthGrant, RevokeResult } from "../store/types.js";
import { isValidChallenge, verifyPkce } from "./pkce.js";
import { isAllowedRedirect, redirectHost } from "./redirects.js";

export const CODE_TTL_MS = 5 * 60_000;
export const DEFAULT_ACCESS_TTL_SECONDS = 3600;
export const DEFAULT_REFRESH_TTL_SECONDS = 90 * 86_400;
export const MAX_REDIRECT_URIS = 5;

export interface OAuthPaths {
  authorize: string;
  token: string;
  register: string;
}

export const DEFAULT_OAUTH_PATHS: OAuthPaths = {
  authorize: "/oauth/authorize",
  token: "/oauth/token",
  register: "/oauth/register",
};

function requireOAuth(guard: Guard): OAuthConfig {
  if (!guard.oauth || !guard.oauthEnabled()) throw new Error("OAuth is not enabled");
  return guard.oauth;
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

export function protectedResourceMetadata(guard: Guard) {
  const oauth = requireOAuth(guard);
  return {
    resource: oauth.resource,
    authorization_servers: [oauth.issuer],
    scopes_supported: [...guard.scopes.all],
    bearer_methods_supported: ["header"],
  };
}

export function authorizationServerMetadata(guard: Guard, paths: OAuthPaths = DEFAULT_OAUTH_PATHS) {
  const oauth = requireOAuth(guard);
  return {
    issuer: oauth.issuer,
    authorization_endpoint: oauth.issuer + paths.authorize,
    token_endpoint: oauth.issuer + paths.token,
    registration_endpoint: oauth.issuer + paths.register,
    scopes_supported: [...guard.scopes.all],
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    authorization_response_iss_parameter_supported: true,
  };
}

/** Value of `WWW-Authenticate` on a 401, pointing a client at the resource metadata. */
export function wwwAuthenticate(guard: Guard): string | null {
  if (!guard.oauth || !guard.oauthEnabled()) return null;
  return `Bearer realm="${guard.brand}", resource_metadata="${guard.oauth.issuer}/.well-known/oauth-protected-resource"`;
}

// ---------------------------------------------------------------------------
// Dynamic client registration
// ---------------------------------------------------------------------------

export type OAuthFailure = { ok: false; status: number; error: string; description: string };

const oauthError = (status: number, error: string, description: string): OAuthFailure => ({ ok: false, status, error, description });

export async function registerClient(
  guard: Guard,
  body: unknown,
): Promise<{ ok: true; client: OAuthClient } | OAuthFailure> {
  const oauth = requireOAuth(guard);
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return oauthError(400, "invalid_client_metadata", "The body must be a JSON object.");
  }
  const metadata = body as Record<string, unknown>;

  const authMethod = metadata.token_endpoint_auth_method;
  if (authMethod !== undefined && authMethod !== "none") {
    return oauthError(400, "invalid_client_metadata", "Only public clients are supported: token_endpoint_auth_method must be none.");
  }

  const uris = metadata.redirect_uris;
  if (!Array.isArray(uris) || uris.length === 0 || uris.length > MAX_REDIRECT_URIS) {
    return oauthError(400, "invalid_redirect_uri", `redirect_uris must list between 1 and ${MAX_REDIRECT_URIS} URIs.`);
  }
  if (!uris.every((uri) => isAllowedRedirect(oauth.redirects, uri))) {
    return oauthError(400, "invalid_redirect_uri", "A redirect URI is not on this server's allowlist.");
  }

  const name = metadata.client_name;
  if (name !== undefined && (typeof name !== "string" || name.length > 100)) {
    return oauthError(400, "invalid_client_metadata", "client_name must be a string of up to 100 characters.");
  }
  const uri = metadata.client_uri;
  if (uri !== undefined && !isHttpsUrl(uri)) {
    return oauthError(400, "invalid_client_metadata", "client_uri must be an https URL of up to 300 characters.");
  }

  const client: OAuthClient = {
    id: `${guard.brand}_cid_${randomSecret(16)}`,
    name: typeof name === "string" ? name : null,
    uri: typeof uri === "string" ? uri : null,
    redirectUris: [...new Set(uris as string[])],
    createdAt: guard.now(),
  };
  await oauth.store.insertClient(client);
  return { ok: true, client };
}

function isHttpsUrl(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 300) return false;
  try {
    return new URL(value).protocol === "https:";
  } catch {
    return false;
  }
}

export function clientRegistrationResponse(client: OAuthClient) {
  return {
    client_id: client.id,
    client_name: client.name ?? undefined,
    redirect_uris: client.redirectUris,
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
  };
}

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

export interface AuthorizeRequest {
  clientId: string;
  redirectUri: string;
  state: string | null;
  codeChallenge: string;
  resource: string;
  /** Scopes the client asked for and this server knows. Empty when it asked for none. */
  requestedScopes: string[];
  /** What to show the person as "who is asking". */
  clientHost: string;
}

export type AuthorizeCheck =
  | { ok: true; request: AuthorizeRequest }
  /** The redirect URI itself cannot be trusted: show an error, never redirect. */
  | { ok: false; kind: "page"; message: string }
  /** The redirect URI is good, the rest is not: send the error back to the client. */
  | { ok: false; kind: "redirect"; location: string };

function redirectWith(oauth: OAuthConfig, redirectUri: string, params: Record<string, string | null>): string {
  const url = new URL(redirectUri);
  for (const [key, value] of Object.entries(params)) {
    if (value !== null) url.searchParams.set(key, value);
  }
  url.searchParams.set("iss", oauth.issuer);
  return url.toString();
}

export async function validateAuthorizeRequest(guard: Guard, params: URLSearchParams): Promise<AuthorizeCheck> {
  const oauth = requireOAuth(guard);
  const clientId = params.get("client_id") ?? "";
  const redirectUri = params.get("redirect_uri") ?? "";
  const state = params.get("state");

  // Until the redirect URI is known to belong to this client, nothing is sent to it: an error that
  // redirects to an unchecked URI is an open redirect.
  if (!isAllowedRedirect(oauth.redirects, redirectUri)) {
    return { ok: false, kind: "page", message: "This sign-in request has a redirect address this server does not accept." };
  }
  const client = clientId ? await oauth.store.getClient(clientId) : null;
  if (!client || !client.redirectUris.includes(redirectUri)) {
    return { ok: false, kind: "page", message: "This sign-in request comes from an application this server does not know." };
  }

  const back = (error: string, description: string): AuthorizeCheck => ({
    ok: false,
    kind: "redirect",
    location: redirectWith(oauth, redirectUri, { error, error_description: description, state }),
  });

  if (params.get("response_type") !== "code") return back("unsupported_response_type", "response_type must be code");
  if (params.get("code_challenge_method") !== "S256") return back("invalid_request", "code_challenge_method must be S256");
  const codeChallenge = params.get("code_challenge");
  if (!isValidChallenge(codeChallenge)) return back("invalid_request", "code_challenge is missing or malformed");
  // A token is good for one resource. A request for another one is refused, not rewritten.
  if (params.get("resource") !== oauth.resource) return back("invalid_target", "resource must be this server's MCP endpoint");

  return {
    ok: true,
    request: {
      clientId,
      redirectUri,
      state,
      codeChallenge,
      resource: oauth.resource,
      requestedScopes: parseScopes(guard.scopes, (params.get("scope") ?? "").split(" ")),
      clientHost: redirectHost(redirectUri),
    },
  };
}

export interface Approval {
  /** The signed-in person, as established by the host application's own session. */
  userId: string;
  kind: Exclude<ActorKind, "agent">;
  /** Required for `owner`. */
  tenantId?: string | null;
  /** What the person ticked on the consent screen. */
  scopes: readonly string[];
  confirmReadAndWrite?: boolean;
}

export type ApprovalResult =
  | { ok: true; location: string }
  | { ok: false; reason: "not_allowed" | "invalid_scopes" | "read_and_write_needs_confirmation" | "invalid_request"; message: string };

/**
 * Issues an authorization code and returns where to send the browser.
 *
 * Everything is checked again here, including what `validateAuthorizeRequest` already checked: the
 * consent form is a POST of its own, and a forged one must not grant more than the page offered.
 */
export async function approveAuthorization(guard: Guard, request: AuthorizeRequest, approval: Approval): Promise<ApprovalResult> {
  const oauth = requireOAuth(guard);
  const refuse = (reason: Exclude<ApprovalResult, { ok: true }>["reason"], message: string): ApprovalResult => ({ ok: false, reason, message });
  const generic = "This account cannot authorize this connection.";

  const client = await oauth.store.getClient(request.clientId);
  if (
    !client ||
    !client.redirectUris.includes(request.redirectUri) ||
    !isAllowedRedirect(oauth.redirects, request.redirectUri) ||
    request.resource !== oauth.resource ||
    !isValidChallenge(request.codeChallenge)
  ) {
    return refuse("invalid_request", "This sign-in request is no longer valid. Start again from the application.");
  }

  const user = await guard.directory.getUser(approval.userId);
  if (!user || user.suspended) return refuse("not_allowed", generic);

  const scopes = parseScopes(guard.scopes, approval.scopes);
  if (scopes.length === 0 || scopes.length !== approval.scopes.length) {
    return refuse("invalid_scopes", "Choose at least one permission.");
  }

  let tenantId: string | null = null;
  if (approval.kind === "advisor") {
    if (!user.staff || approval.tenantId) return refuse("not_allowed", generic);
  } else {
    const tenant = approval.tenantId ? await guard.directory.getTenant(approval.tenantId) : null;
    const role = tenant && !tenant.suspended ? await guard.directory.getMembership(user.id, tenant.id) : null;
    if (!tenant || !role) return refuse("not_allowed", generic);
    if (role === "viewer" && scopesOfNature(guard.scopes, scopes, "write", "propose").length > 0) {
      return refuse("invalid_scopes", "Your role in this tenant allows read permissions only.");
    }
    tenantId = tenant.id;
  }

  if (mixesReadAndWrite(guard.scopes, scopes) && approval.confirmReadAndWrite !== true) {
    return refuse(
      "read_and_write_needs_confirmation",
      "This connection would both read text written by outsiders and change data. Confirm to allow both.",
    );
  }

  const now = guard.now();
  const secret = randomSecret();
  const hashed = hashToken(secret, guard.pepper);
  const code: AuthorizationCode = {
    id: guard.newId(),
    hash: hashed.hash,
    hashVersion: hashed.version,
    clientId: client.id,
    userId: user.id,
    kind: approval.kind,
    tenantId,
    scopes,
    redirectUri: request.redirectUri,
    codeChallenge: request.codeChallenge,
    resource: request.resource,
    expiresAt: new Date(now.getTime() + CODE_TTL_MS),
    consumedAt: null,
    createdAt: now,
  };
  await oauth.store.insertCode(code);
  return { ok: true, location: redirectWith(oauth, request.redirectUri, { code: secret, state: request.state }) };
}

export function denyAuthorization(guard: Guard, request: AuthorizeRequest): string {
  return redirectWith(requireOAuth(guard), request.redirectUri, {
    error: "access_denied",
    error_description: "The request was declined",
    state: request.state,
  });
}

// ---------------------------------------------------------------------------
// Token endpoint
// ---------------------------------------------------------------------------

export interface TokenResponseBody {
  access_token: string;
  refresh_token: string;
  token_type: "Bearer";
  expires_in: number;
  scope: string;
}

export type TokenResult = { ok: true; body: TokenResponseBody } | OAuthFailure;

const invalidGrant = (): OAuthFailure => oauthError(400, "invalid_grant", "The grant is invalid, expired or already used.");

export async function exchangeToken(guard: Guard, params: Readonly<Record<string, string | undefined>>): Promise<TokenResult> {
  const oauth = requireOAuth(guard);
  if (params.grant_type === "authorization_code") return exchangeCode(guard, oauth, params);
  if (params.grant_type === "refresh_token") return refresh(guard, oauth, params);
  return oauthError(400, "unsupported_grant_type", "grant_type must be authorization_code or refresh_token.");
}

async function exchangeCode(guard: Guard, oauth: OAuthConfig, params: Readonly<Record<string, string | undefined>>): Promise<TokenResult> {
  const { code, client_id: clientId, code_verifier: verifier, redirect_uri: redirectUri, resource } = params;
  if (!code || !clientId || !verifier || !redirectUri) {
    return oauthError(400, "invalid_request", "code, client_id, code_verifier and redirect_uri are required.");
  }
  if (resource !== undefined && resource !== oauth.resource) {
    return oauthError(400, "invalid_target", "resource must be this server's MCP endpoint.");
  }
  const client = await oauth.store.getClient(clientId);
  if (!client) return oauthError(400, "invalid_client", "Unknown client.");

  let stored: AuthorizationCode | null = null;
  for (const candidate of candidateHashes(code, guard.pepper)) {
    stored = await oauth.store.findCodeByHash(candidate.hash);
    if (stored) break;
  }
  if (!stored || stored.clientId !== client.id) return invalidGrant();

  const now = guard.now();
  if (stored.consumedAt) {
    // A code presented twice was seen by two parties. Whoever was first holds tokens that may not
    // be theirs, so those go too.
    await oauth.store.revokeFamily(stored.id, now);
    return invalidGrant();
  }
  if (
    stored.expiresAt.getTime() <= now.getTime() ||
    stored.redirectUri !== redirectUri ||
    stored.resource !== oauth.resource ||
    !verifyPkce(verifier, stored.codeChallenge)
  ) {
    return invalidGrant();
  }
  // Compare-and-swap: of two requests racing with the same code, one gets tokens.
  if (!(await oauth.store.consumeCode(stored.id, now))) return invalidGrant();

  return { ok: true, body: await issueGrant(guard, oauth, { ...stored, familyId: stored.id }) };
}

async function refresh(guard: Guard, oauth: OAuthConfig, params: Readonly<Record<string, string | undefined>>): Promise<TokenResult> {
  const { refresh_token: refreshToken, client_id: clientId, resource } = params;
  if (!refreshToken || !clientId) return oauthError(400, "invalid_request", "refresh_token and client_id are required.");
  if (resource !== undefined && resource !== oauth.resource) {
    return oauthError(400, "invalid_target", "resource must be this server's MCP endpoint.");
  }
  if (classifyToken(guard.brand, refreshToken) !== "refresh") return invalidGrant();

  let grant: OAuthGrant | null = null;
  for (const candidate of candidateHashes(refreshToken, guard.pepper)) {
    grant = await oauth.store.findGrantByRefreshHash(candidate.hash);
    if (grant) break;
  }
  // A wrong client gets the same answer as an unknown token.
  if (!grant || grant.clientId !== clientId) return invalidGrant();

  const now = guard.now();
  if (grant.rotatedAt) {
    // This refresh token was already exchanged once. A public client cannot prove which of the two
    // presenters is the real one, so every token descended from this authorization is revoked and
    // the person signs in again.
    await oauth.store.revokeFamily(grant.familyId, now);
    return invalidGrant();
  }
  if (grant.revokedAt || grant.refreshExpiresAt.getTime() <= now.getTime()) return invalidGrant();
  // Of two requests racing with the same token, one wins. The loser is told to stop; the family is
  // kept, because a client retrying a dropped connection is not an attack.
  if (!(await oauth.store.rotateGrant(grant.id, now))) return invalidGrant();

  return { ok: true, body: await issueGrant(guard, oauth, grant) };
}

async function issueGrant(
  guard: Guard,
  oauth: OAuthConfig,
  source: Pick<OAuthGrant, "familyId" | "clientId" | "userId" | "kind" | "tenantId" | "scopes">,
): Promise<TokenResponseBody> {
  const now = guard.now();
  const accessTtl = oauth.accessTtlSeconds ?? DEFAULT_ACCESS_TTL_SECONDS;
  const refreshTtl = oauth.refreshTtlSeconds ?? DEFAULT_REFRESH_TTL_SECONDS;
  const access = generateToken(guard.brand, "access");
  const refreshToken = generateToken(guard.brand, "refresh");
  const accessHash = hashToken(access.token, guard.pepper);

  await oauth.store.insertGrant({
    id: guard.newId(),
    familyId: source.familyId,
    clientId: source.clientId,
    userId: source.userId,
    kind: source.kind,
    tenantId: source.tenantId,
    scopes: [...source.scopes],
    accessHash: accessHash.hash,
    refreshHash: hashToken(refreshToken.token, guard.pepper).hash,
    hashVersion: accessHash.version,
    expiresAt: new Date(now.getTime() + accessTtl * 1000),
    refreshExpiresAt: new Date(now.getTime() + refreshTtl * 1000),
    revokedAt: null,
    rotatedAt: null,
    createdAt: now,
  });
  return {
    access_token: access.token,
    refresh_token: refreshToken.token,
    token_type: "Bearer",
    expires_in: accessTtl,
    scope: source.scopes.join(" "),
  };
}

// ---------------------------------------------------------------------------
// Connections
// ---------------------------------------------------------------------------

export interface ConnectionSummary {
  id: string;
  clientId: string;
  tenantId: string | null;
  scopes: string[];
  status: "active" | "revoked" | "expired";
  createdAt: Date;
}

/**
 * A person's connections, one per authorization: only the current token pair of each family.
 * Available even when OAuth is switched off, so that what was granted can still be seen and revoked.
 */
export async function listConnections(guard: Guard, userId: string): Promise<ConnectionSummary[]> {
  if (!guard.oauth) return [];
  const now = guard.now();
  const latest = new Map<string, OAuthGrant>();
  for (const grant of await guard.oauth.store.listGrants(userId)) {
    const chosen = latest.get(grant.familyId);
    // The pair that was not exchanged for a newer one is the current one. Creation time alone
    // cannot say: a rotation can land in the same millisecond.
    if (!chosen || (chosen.rotatedAt && !grant.rotatedAt)) latest.set(grant.familyId, grant);
  }
  return [...latest.values()].map((grant) => {
    const usability = tokenUsability({ revokedAt: grant.revokedAt, expiresAt: grant.refreshExpiresAt }, now);
    return {
      id: grant.id,
      clientId: grant.clientId,
      tenantId: grant.tenantId,
      scopes: [...grant.scopes],
      status: usability === "ok" ? "active" : usability,
      createdAt: grant.createdAt,
    };
  });
}

/** Revokes a connection of this user. Someone else's id answers `not_found`, like a missing one. */
export async function revokeConnection(guard: Guard, userId: string, grantId: string): Promise<RevokeResult> {
  if (!guard.oauth) return "not_found";
  return guard.oauth.store.revokeGrant(grantId, userId, guard.now());
}
