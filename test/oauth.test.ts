import { describe, expect, it } from "vitest";

import { connect, rawRequest } from "../src/example/client.js";
import { challengeFor } from "../src/oauth/pkce.js";
import {
  approveAuthorization,
  denyAuthorization,
  exchangeToken,
  listConnections,
  registerClient,
  revokeConnection,
  validateAuthorizeRequest,
} from "../src/oauth/server.js";
import type { AuthorizeRequest, TokenResponseBody } from "../src/oauth/server.js";
import { FERNHILL, JUN, LARKSPUR, MARA, NELL, harbor } from "./helpers.js";
import type { TestHarbor } from "./helpers.js";

const REDIRECT = "https://client.example.test/callback";
const VERIFIER = "v".repeat(64);

async function client(h: TestHarbor): Promise<string> {
  const result = await registerClient(h.guard, { redirect_uris: [REDIRECT], client_name: "Example client" });
  if (!result.ok) throw new Error(result.error);
  return result.client.id;
}

function authorizeParams(h: TestHarbor, clientId: string, extra: Record<string, string> = {}): URLSearchParams {
  return new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: REDIRECT,
    code_challenge: challengeFor(VERIFIER),
    code_challenge_method: "S256",
    resource: h.mcpUrl,
    state: "st-123",
    ...extra,
  });
}

async function authorizeRequest(h: TestHarbor, clientId: string): Promise<AuthorizeRequest> {
  const check = await validateAuthorizeRequest(h.guard, authorizeParams(h, clientId));
  if (!check.ok) throw new Error("authorize request refused");
  return check.request;
}

/** Runs the flow up to an authorization code. */
async function codeFor(h: TestHarbor, clientId: string, userId = NELL, scopes = ["orders:read"]): Promise<string> {
  const approved = await approveAuthorization(h.guard, await authorizeRequest(h, clientId), {
    userId,
    kind: userId === MARA ? "advisor" : "owner",
    tenantId: userId === MARA ? null : FERNHILL,
    scopes,
  });
  if (!approved.ok) throw new Error(approved.reason);
  return new URL(approved.location).searchParams.get("code")!;
}

const codeGrant = (clientId: string, code: string, extra: Record<string, string> = {}) => ({
  grant_type: "authorization_code",
  client_id: clientId,
  code,
  code_verifier: VERIFIER,
  redirect_uri: REDIRECT,
  ...extra,
});

async function tokensFor(h: TestHarbor, clientId: string, userId = NELL, scopes = ["orders:read"]): Promise<TokenResponseBody> {
  const result = await exchangeToken(h.guard, codeGrant(clientId, await codeFor(h, clientId, userId, scopes)));
  if (!result.ok) throw new Error(result.error);
  return result.body;
}

describe("client registration", () => {
  it("registers a public client with allowlisted redirect URIs and issues no secret", async () => {
    const h = harbor();
    const result = await registerClient(h.guard, { redirect_uris: [REDIRECT, "http://127.0.0.1:7777/cb"], client_name: "Example" });
    if (!result.ok) throw new Error(result.error);
    expect(result.client.id).toMatch(/^harbor_cid_/);
    expect(JSON.stringify(result.client)).not.toContain("secret");
  });

  it.each([
    [{ redirect_uris: ["https://evil.example.test/callback"] }, "invalid_redirect_uri"],
    [{ redirect_uris: [REDIRECT, "https://evil.example.test/callback"] }, "invalid_redirect_uri"],
    [{ redirect_uris: [] }, "invalid_redirect_uri"],
    [{ redirect_uris: Array.from({ length: 6 }, () => REDIRECT) }, "invalid_redirect_uri"],
    [{ redirect_uris: [REDIRECT], token_endpoint_auth_method: "client_secret_basic" }, "invalid_client_metadata"],
    [{ redirect_uris: [REDIRECT], client_name: "n".repeat(101) }, "invalid_client_metadata"],
    [{ redirect_uris: [REDIRECT], client_uri: "javascript:alert(1)" }, "invalid_client_metadata"],
    [[], "invalid_client_metadata"],
  ])("refuses %j", async (body, error) => {
    const h = harbor();
    expect(await registerClient(h.guard, body)).toMatchObject({ ok: false, error });
    expect(h.oauthStore.clients).toEqual([]);
  });
});

describe("the authorization request", () => {
  it("never redirects to an address it has not verified", async () => {
    const h = harbor();
    const clientId = await client(h);
    const unlisted = await validateAuthorizeRequest(h.guard, authorizeParams(h, clientId, { redirect_uri: "https://evil.example.test/callback" }));
    expect(unlisted).toMatchObject({ ok: false, kind: "page" });
    // Allowlisted, but not registered by THIS client.
    const borrowed = await validateAuthorizeRequest(h.guard, authorizeParams(h, clientId, { redirect_uri: "http://localhost:9999/cb" }));
    expect(borrowed).toMatchObject({ ok: false, kind: "page" });
    const unknownClient = await validateAuthorizeRequest(h.guard, authorizeParams(h, "harbor_cid_nope"));
    expect(unknownClient).toMatchObject({ ok: false, kind: "page" });
  });

  it.each([
    [{ response_type: "token" }, "unsupported_response_type"],
    [{ code_challenge_method: "plain" }, "invalid_request"],
    [{ code_challenge: "short" }, "invalid_request"],
    [{ resource: "https://other.example.test/mcp" }, "invalid_target"],
  ])("sends %j back to the client as an error, with the state", async (override, error) => {
    const h = harbor();
    const check = await validateAuthorizeRequest(h.guard, authorizeParams(h, await client(h), override));
    if (check.ok || check.kind !== "redirect") throw new Error("expected a redirect");
    const location = new URL(check.location);
    expect(location.origin + location.pathname).toBe(REDIRECT);
    expect(location.searchParams.get("error")).toBe(error);
    expect(location.searchParams.get("state")).toBe("st-123");
  });

  it("shows the person the host that will receive the code, not what the client calls itself", async () => {
    const h = harbor();
    expect((await authorizeRequest(h, await client(h))).clientHost).toBe("client.example.test");
  });
});

describe("consent", () => {
  it("issues a code and returns to the client with the state and the issuer", async () => {
    const h = harbor();
    const request = await authorizeRequest(h, await client(h));
    const approved = await approveAuthorization(h.guard, request, { userId: NELL, kind: "owner", tenantId: FERNHILL, scopes: ["orders:read"] });
    if (!approved.ok) throw new Error(approved.reason);
    const location = new URL(approved.location);
    expect(location.searchParams.get("state")).toBe("st-123");
    expect(location.searchParams.get("iss")).toBe("http://localhost:8787");
    const code = location.searchParams.get("code")!;
    expect(JSON.stringify(h.oauthStore.codes)).not.toContain(code);
  });

  it("grants nothing a forged form asks for beyond what the person may do", async () => {
    const h = harbor();
    const request = await authorizeRequest(h, await client(h));
    const owner = { userId: NELL, kind: "owner" as const, tenantId: FERNHILL };

    expect(await approveAuthorization(h.guard, request, { ...owner, scopes: ["orders:read", "made:up"] })).toMatchObject({ reason: "invalid_scopes" });
    expect(await approveAuthorization(h.guard, request, { ...owner, scopes: [] })).toMatchObject({ reason: "invalid_scopes" });
    expect(await approveAuthorization(h.guard, request, { ...owner, tenantId: LARKSPUR, scopes: ["orders:read"] })).toMatchObject({ reason: "not_allowed" });
    expect(await approveAuthorization(h.guard, request, { userId: NELL, kind: "advisor", scopes: ["orders:read"] })).toMatchObject({ reason: "not_allowed" });
    expect(await approveAuthorization(h.guard, request, { userId: JUN, kind: "owner", tenantId: FERNHILL, scopes: ["stock:propose"] })).toMatchObject({ reason: "invalid_scopes" });
    expect(await approveAuthorization(h.guard, request, { ...owner, scopes: ["orders:read", "orders:write"] })).toMatchObject({ reason: "read_and_write_needs_confirmation" });
    expect(await approveAuthorization(h.guard, { ...request, redirectUri: "http://localhost:9999/cb" }, { ...owner, scopes: ["orders:read"] })).toMatchObject({ reason: "invalid_request" });
    expect(h.oauthStore.codes).toEqual([]);
  });

  it("does not let a suspended account connect anything", async () => {
    const h = harbor();
    const request = await authorizeRequest(h, await client(h));
    h.world.suspendUser(NELL);
    expect(await approveAuthorization(h.guard, request, { userId: NELL, kind: "owner", tenantId: FERNHILL, scopes: ["orders:read"] })).toMatchObject({ reason: "not_allowed" });
  });

  it("reports a refusal back to the client", async () => {
    const h = harbor();
    const location = new URL((await denyAuthorization(h.guard, await authorizeRequest(h, await client(h))))!);
    expect(location.searchParams.get("error")).toBe("access_denied");
    expect(location.searchParams.get("state")).toBe("st-123");
  });
});

describe("exchanging a code", () => {
  it("returns an access token that works on the MCP endpoint, within its scopes", async () => {
    const h = harbor();
    const tokens = await tokensFor(h, await client(h));
    expect(tokens).toMatchObject({ token_type: "Bearer", expires_in: 3600, scope: "orders:read" });
    expect(tokens.access_token).toMatch(/^harbor_atk_/);
    expect(JSON.stringify(h.oauthStore.grants)).not.toContain(tokens.access_token);
    expect(JSON.stringify(h.oauthStore.grants)).not.toContain(tokens.refresh_token);

    const mcp = await connect(h, tokens.access_token);
    expect(await mcp.toolNames()).toEqual(["list_tenants", "read_orders"]);
    expect((await mcp.call("read_orders", { limit: 1 })).body.tenantId).toBe(FERNHILL);
  });

  it("refuses a wrong verifier, redirect, client or resource, and an expired code", async () => {
    const h = harbor();
    const clientId = await client(h);
    const other = await client(h);
    const attempt = async (extra: Record<string, string>, advance = 0) => {
      const code = await codeFor(h, clientId);
      h.advance(advance);
      return exchangeToken(h.guard, codeGrant(clientId, code, extra));
    };

    expect(await attempt({ code_verifier: "w".repeat(64) })).toMatchObject({ error: "invalid_grant" });
    expect(await attempt({ code_verifier: "short" })).toMatchObject({ error: "invalid_grant" });
    expect(await attempt({ redirect_uri: "http://localhost:9999/cb" })).toMatchObject({ error: "invalid_grant" });
    expect(await attempt({ client_id: other })).toMatchObject({ error: "invalid_grant" });
    expect(await attempt({ client_id: "harbor_cid_nope" })).toMatchObject({ error: "invalid_client" });
    expect(await attempt({ resource: "https://other.example.test/mcp" })).toMatchObject({ error: "invalid_target" });
    expect(await attempt({}, 5 * 60_000)).toMatchObject({ error: "invalid_grant" });
    expect(await exchangeToken(h.guard, { grant_type: "password" })).toMatchObject({ error: "unsupported_grant_type" });
    expect(h.oauthStore.grants).toEqual([]);
  });

  it("gives tokens to one of two requests racing with the same code", async () => {
    const h = harbor();
    const clientId = await client(h);
    const code = await codeFor(h, clientId);
    const results = await Promise.all([exchangeToken(h.guard, codeGrant(clientId, code)), exchangeToken(h.guard, codeGrant(clientId, code))]);
    expect(results.filter((result) => result.ok)).toHaveLength(1);
  });

  it("revokes the tokens already issued when a code is presented a second time", async () => {
    const h = harbor();
    const clientId = await client(h);
    const code = await codeFor(h, clientId);
    const first = await exchangeToken(h.guard, codeGrant(clientId, code));
    if (!first.ok) throw new Error(first.error);
    expect((await rawRequest(h, first.body.access_token, { body: "{}" })).status).not.toBe(401);

    expect(await exchangeToken(h.guard, codeGrant(clientId, code))).toMatchObject({ error: "invalid_grant" });
    expect((await rawRequest(h, first.body.access_token, { body: "{}" })).status).toBe(401);
  });
});

describe("refreshing", () => {
  const refreshGrant = (clientId: string, refreshToken: string) => ({ grant_type: "refresh_token", client_id: clientId, refresh_token: refreshToken });

  it("rotates: a new pair is issued and the old access token stops working", async () => {
    const h = harbor();
    const clientId = await client(h);
    const first = await tokensFor(h, clientId);
    const second = await exchangeToken(h.guard, refreshGrant(clientId, first.refresh_token));
    if (!second.ok) throw new Error(second.error);

    expect(second.body.scope).toBe("orders:read");
    expect(second.body.access_token).not.toBe(first.access_token);
    expect((await rawRequest(h, first.access_token, { body: "{}" })).status).toBe(401);
    expect((await rawRequest(h, second.body.access_token, { body: "{}" })).status).not.toBe(401);
  });

  it("revokes the whole family when a rotated refresh token comes back", async () => {
    const h = harbor();
    const clientId = await client(h);
    const first = await tokensFor(h, clientId);
    const second = await exchangeToken(h.guard, refreshGrant(clientId, first.refresh_token));
    if (!second.ok) throw new Error(second.error);

    // Someone presents the old one again: a thief, or the client the thief stole from.
    expect(await exchangeToken(h.guard, refreshGrant(clientId, first.refresh_token))).toMatchObject({ error: "invalid_grant" });
    // Neither side keeps a working token.
    expect((await rawRequest(h, second.body.access_token, { body: "{}" })).status).toBe(401);
    expect(await exchangeToken(h.guard, refreshGrant(clientId, second.body.refresh_token))).toMatchObject({ error: "invalid_grant" });
  });

  it("lets one of two racing refreshes win and keeps the family alive", async () => {
    const h = harbor();
    const clientId = await client(h);
    const first = await tokensFor(h, clientId);
    const results = await Promise.all([
      exchangeToken(h.guard, refreshGrant(clientId, first.refresh_token)),
      exchangeToken(h.guard, refreshGrant(clientId, first.refresh_token)),
    ]);
    const winners = results.filter((result) => result.ok);
    expect(winners).toHaveLength(1);
    const winner = winners[0]!;
    if (!winner.ok) throw new Error("unreachable");
    expect((await rawRequest(h, winner.body.access_token, { body: "{}" })).status).not.toBe(401);
  });

  it("gives a wrong client, an unknown token and an expired one the same answer", async () => {
    const h = harbor();
    const clientId = await client(h);
    const other = await client(h);
    const tokens = await tokensFor(h, clientId);

    const wrongClient = await exchangeToken(h.guard, refreshGrant(other, tokens.refresh_token));
    const unknown = await exchangeToken(h.guard, refreshGrant(clientId, `harbor_rtk_${"z".repeat(43)}`));
    const accessAsRefresh = await exchangeToken(h.guard, refreshGrant(clientId, tokens.access_token));
    h.advance(90 * 86_400_000);
    const expired = await exchangeToken(h.guard, refreshGrant(clientId, tokens.refresh_token));
    expect(new Set([wrongClient, unknown, accessAsRefresh, expired].map((result) => JSON.stringify(result))).size).toBe(1);
    expect(wrongClient).toMatchObject({ error: "invalid_grant" });
  });
});

describe("after the grant", () => {
  it("expires the access token and re-reads the person's standing on every request", async () => {
    const h = harbor();
    const tokens = await tokensFor(h, await client(h));
    h.world.setRole(NELL, FERNHILL, null);
    expect((await rawRequest(h, tokens.access_token, { body: "{}" })).status).toBe(401);

    const again = harbor();
    const fresh = await tokensFor(again, await client(again));
    again.advance(3600_000);
    expect((await rawRequest(again, fresh.access_token, { body: "{}" })).status).toBe(401);
  });

  it("switches off already issued tokens with the feature, at no storage cost", async () => {
    let enabled = true;
    const base = harbor();
    const h = harbor({
      overrides: { oauth: { store: base.oauthStore, issuer: "http://localhost:8787", resource: base.mcpUrl, redirects: { exact: [REDIRECT] }, enabled: () => enabled } },
    });
    const tokens = await tokensFor(h, await client(h));
    expect((await rawRequest(h, tokens.access_token, { body: "{}" })).status).not.toBe(401);

    enabled = false;
    let lookups = 0;
    base.oauthStore.findGrantByAccessHash = async () => {
      lookups += 1;
      return null;
    };
    const refused = await rawRequest(h, tokens.access_token, { body: "{}" });
    expect(refused.status).toBe(401);
    expect(refused.headers.get("www-authenticate")).toBeNull();
    expect(lookups).toBe(0);
  });

  it("lists a person's connections, one per authorization, and lets them revoke their own", async () => {
    const h = harbor();
    const clientId = await client(h);
    const tokens = await tokensFor(h, clientId);
    await exchangeToken(h.guard, { grant_type: "refresh_token", client_id: clientId, refresh_token: tokens.refresh_token });
    await tokensFor(h, clientId, MARA, ["stock:read"]);

    const mine = await listConnections(h.guard, NELL);
    expect(mine).toHaveLength(1);
    expect(mine[0]).toMatchObject({ status: "active", tenantId: FERNHILL, scopes: ["orders:read"] });
    expect(JSON.stringify(mine)).not.toMatch(/hash/i);

    expect(await revokeConnection(h.guard, MARA, mine[0]!.id)).toBe("not_found");
    expect(await revokeConnection(h.guard, NELL, mine[0]!.id)).toBe("revoked");
    expect((await listConnections(h.guard, NELL))[0]!.status).toBe("revoked");
  });
});

describe("the OAuth endpoints", () => {
  const get = (h: TestHarbor, path: string) => h.fetch(new Request(`http://localhost:8787${path}`));
  const post = (h: TestHarbor, path: string, body: string, type = "application/json") =>
    h.fetch(new Request(`http://localhost:8787${path}`, { method: "POST", body, headers: { "content-type": type } }));

  it("publishes metadata a client can discover the flow from", async () => {
    const h = harbor();
    const resource = (await (await get(h, "/.well-known/oauth-protected-resource/mcp")).json()) as Record<string, unknown>;
    expect(resource).toMatchObject({ resource: h.mcpUrl, authorization_servers: ["http://localhost:8787"], bearer_methods_supported: ["header"] });
    const server = (await (await get(h, "/.well-known/oauth-authorization-server")).json()) as Record<string, unknown>;
    expect(server).toMatchObject({
      issuer: "http://localhost:8787",
      token_endpoint: "http://localhost:8787/oauth/token",
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
    });
  });

  it("runs registration and the token exchange over HTTP, form-encoded or JSON, never cached", async () => {
    const h = harbor();
    const registered = await post(h, "/oauth/register", JSON.stringify({ redirect_uris: [REDIRECT] }));
    expect(registered.status).toBe(201);
    const { client_id: clientId } = (await registered.json()) as { client_id: string };

    const form = new URLSearchParams(codeGrant(clientId, await codeFor(h, clientId))).toString();
    const viaForm = await post(h, "/oauth/token", form, "application/x-www-form-urlencoded");
    expect(viaForm.status).toBe(200);
    expect(viaForm.headers.get("cache-control")).toBe("no-store");

    const viaJson = await post(h, "/oauth/token", JSON.stringify(codeGrant(clientId, await codeFor(h, clientId))));
    expect(viaJson.status).toBe(200);

    const bad = await post(h, "/oauth/token", "{not json");
    expect(bad.status).toBe(400);
    expect(bad.headers.get("cache-control")).toBe("no-store");
  });

  it("limits registrations and token calls before reading the body", async () => {
    const h = harbor();
    const statuses = [];
    for (let i = 0; i < 7; i += 1) statuses.push((await post(h, "/oauth/register", JSON.stringify({ redirect_uris: [REDIRECT] }))).status);
    expect(statuses).toEqual([201, 201, 201, 201, 201, 429, 429]);
    expect(h.oauthStore.clients).toHaveLength(5);
  });

  it("answers 404 on every endpoint when the feature is off, and does not match look-alike paths", async () => {
    const base = harbor();
    const off = harbor({
      overrides: { oauth: { store: base.oauthStore, issuer: "http://localhost:8787", resource: base.mcpUrl, redirects: {}, enabled: () => false } },
    });
    for (const path of ["/.well-known/oauth-protected-resource", "/.well-known/oauth-authorization-server"]) {
      expect((await get(off, path)).status).toBe(404);
    }
    expect((await post(off, "/oauth/register", JSON.stringify({ redirect_uris: [REDIRECT] }))).status).toBe(404);
    expect((await post(off, "/oauth/token", "grant_type=refresh_token")).status).toBe(404);
    expect(base.oauthStore.clients).toEqual([]);

    expect((await post(base, "/oauth/registerx", "{}")).status).toBe(404);
    expect((await post(base, "/oauth/token/extra", "{}")).status).toBe(404);
  });
});
