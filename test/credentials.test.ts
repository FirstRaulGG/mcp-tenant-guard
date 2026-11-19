import { describe, expect, it } from "vitest";

import { defineScopes } from "../src/core/scopes.js";
import { generateToken, hashToken } from "../src/core/tokens.js";
import { authenticate } from "../src/guard/authenticate.js";
import { createGuard } from "../src/guard/guard.js";
import { issueCredential, listCredentials, revokeCredential } from "../src/guard/issue.js";
import { MemoryAuditStore, MemoryCredentialStore } from "../src/store/memory.js";
import { FERNHILL, JUN, LARKSPUR, MARA, NELL, ODILE, TOMAS, advisorToken, agentToken, harbor, issue, ownerToken } from "./helpers.js";

const bearer = (token: string) => `Bearer ${token}`;

describe("createGuard", () => {
  const base = {
    brand: "acme",
    scopes: defineScopes({ read: ["a:read"], write: ["a:write"] }),
    directory: harbor().world.directory,
    credentials: new MemoryCredentialStore(),
    audit: new MemoryAuditStore(),
  };

  it("will not start without a pepper unless that was chosen", () => {
    expect(() => createGuard(base)).toThrow(/pepper/);
    expect(() => createGuard({ ...base, pepper: "short" })).toThrow(/32/);
    expect(createGuard({ ...base, allowUnpepperedHashes: true }).pepper).toBeNull();
  });

  it("will not start with an agent that could write", () => {
    const config = { ...base, allowUnpepperedHashes: true };
    expect(() => createGuard({ ...config, agents: { bot: { scopes: ["a:write"] } } })).toThrow(/write scope/);
    expect(() => createGuard({ ...config, agents: { bot: { scopes: ["b:read"] } } })).toThrow(/unknown scope/);
  });

  it("will not start with an OAuth issuer that is not https", () => {
    const oauth = { store: harbor().oauthStore, redirects: {}, issuer: "http://app.example.test", resource: "https://app.example.test/mcp" };
    expect(() => createGuard({ ...base, allowUnpepperedHashes: true, oauth })).toThrow(/https/);
  });
});

describe("issuing", () => {
  it("returns the token once and stores only its hash", async () => {
    const h = harbor();
    const result = await issueCredential(h.guard, { kind: "advisor", userId: MARA, name: "laptop", scopes: ["orders:read"] });
    if (!result.ok) throw new Error(result.reason);

    expect(result.token).toMatch(/^harbor_pat_/);
    expect(result.credential).toMatchObject({ kind: "advisor", name: "laptop", status: "active", scopes: ["orders:read"] });
    const stored = JSON.stringify(h.credentials.rows);
    expect(stored).not.toContain(result.token);
    expect(h.credentials.rows[0]!.hashVersion).toBe(2);
    expect(JSON.stringify(await listCredentials(h.guard, MARA))).not.toContain(h.credentials.rows[0]!.hash);
  });

  it("asks for confirmation before one token can both read outside text and write", async () => {
    const h = harbor();
    const request = { kind: "owner" as const, userId: NELL, tenantId: FERNHILL, name: "both", scopes: ["orders:read", "orders:write"] };
    expect(await issueCredential(h.guard, request)).toMatchObject({ ok: false, reason: "read_and_write_needs_confirmation" });
    expect((await issueCredential(h.guard, { ...request, confirmReadAndWrite: true })).ok).toBe(true);
    // Neither half alone needs it.
    expect((await issueCredential(h.guard, { ...request, scopes: ["orders:write"] })).ok).toBe(true);
    expect((await issueCredential(h.guard, { ...request, scopes: ["orders:read", "stock:read"] })).ok).toBe(true);
  });

  it("refuses unknown scopes, an empty list, a bad lifetime and a bad name", async () => {
    const h = harbor();
    const base = { kind: "advisor" as const, userId: MARA, name: "x", scopes: ["orders:read"] };
    expect(await issueCredential(h.guard, { ...base, scopes: ["orders:read", "made:up"] })).toMatchObject({ reason: "invalid_scopes" });
    expect(await issueCredential(h.guard, { ...base, scopes: [] })).toMatchObject({ reason: "invalid_scopes" });
    expect(await issueCredential(h.guard, { ...base, ttlDays: 400 })).toMatchObject({ reason: "invalid_ttl" });
    expect(await issueCredential(h.guard, { ...base, name: "  " })).toMatchObject({ reason: "invalid_name" });
  });

  it("issues only what the person could do themselves", async () => {
    const h = harbor();
    // Not staff.
    expect(await issueCredential(h.guard, { kind: "advisor", userId: NELL, name: "x", scopes: ["orders:read"] })).toMatchObject({ reason: "not_allowed" });
    // Not a member of that shop.
    expect(await issueCredential(h.guard, { kind: "owner", userId: NELL, tenantId: LARKSPUR, name: "x", scopes: ["orders:read"] })).toMatchObject({ reason: "not_allowed" });
    // A viewer cannot mint a proposal scope.
    expect(await issueCredential(h.guard, { kind: "owner", userId: JUN, tenantId: FERNHILL, name: "x", scopes: ["stock:propose"] })).toMatchObject({ reason: "invalid_scopes" });
    // An advisor cannot delegate an agent to a shop that is not theirs; an admin can.
    expect(await issueCredential(h.guard, { kind: "agent", userId: MARA, tenantId: LARKSPUR, agentName: "restock", name: "x" })).toMatchObject({ reason: "not_allowed" });
    expect((await issueCredential(h.guard, { kind: "agent", userId: TOMAS, tenantId: LARKSPUR, agentName: "restock", name: "x" })).ok).toBe(true);
    // An owner cannot delegate an agent at all.
    expect(await issueCredential(h.guard, { kind: "agent", userId: NELL, tenantId: FERNHILL, agentName: "restock", name: "x" })).toMatchObject({ reason: "not_allowed" });
  });

  it("takes an agent's scopes from the table, never from the request", async () => {
    const h = harbor();
    const result = await issueCredential(h.guard, {
      kind: "agent", userId: MARA, tenantId: FERNHILL, agentName: "restock", name: "nightly", scopes: ["orders:write", "orders:read"],
    });
    if (!result.ok) throw new Error(result.reason);
    expect(result.token).toMatch(/^harbor_agt_/);
    expect(result.credential.scopes).toEqual(["stock:read", "stock:propose"]);
  });

  it("caps active tokens per person, counting agent tokens too", async () => {
    const h = harbor({ overrides: { maxActiveCredentialsPerUser: 2 } });
    await advisorToken(h);
    await agentToken(h);
    expect(await issueCredential(h.guard, { kind: "advisor", userId: MARA, name: "third", scopes: ["orders:read"] })).toMatchObject({ reason: "too_many_credentials" });
    const [first] = await listCredentials(h.guard, MARA);
    await revokeCredential(h.guard, MARA, first!.id);
    expect((await issueCredential(h.guard, { kind: "advisor", userId: MARA, name: "third", scopes: ["orders:read"] })).ok).toBe(true);
  });

  it("revokes only the owner's own token, and cannot tell a foreign id from a missing one", async () => {
    const h = harbor();
    const token = await advisorToken(h);
    const [credential] = await listCredentials(h.guard, MARA);

    expect(await revokeCredential(h.guard, NELL, credential!.id)).toBe("not_found");
    expect(await revokeCredential(h.guard, MARA, "no-such-id")).toBe("not_found");
    expect(await authenticate(h.guard, bearer(token))).not.toBeNull();

    expect(await revokeCredential(h.guard, MARA, credential!.id)).toBe("revoked");
    expect(await revokeCredential(h.guard, MARA, credential!.id)).toBe("already_revoked");
    expect(await authenticate(h.guard, bearer(token))).toBeNull();
  });
});

describe("authenticating", () => {
  it("builds the actor from the stored credential", async () => {
    const h = harbor();
    expect(await authenticate(h.guard, bearer(await advisorToken(h)))).toMatchObject({
      kind: "advisor", userId: MARA, tenantId: null, fullPortfolio: false, scopes: ["orders:read", "stock:read"],
    });
    expect(await authenticate(h.guard, bearer(await issue(h, { kind: "advisor", userId: TOMAS, scopes: ["orders:read"] })))).toMatchObject({ fullPortfolio: true });
    expect(await authenticate(h.guard, bearer(await ownerToken(h)))).toMatchObject({ kind: "owner", tenantId: FERNHILL, role: "admin" });
    expect(await authenticate(h.guard, bearer(await agentToken(h)))).toMatchObject({
      kind: "agent", userId: MARA, agentName: "restock", tenantId: FERNHILL, scopes: ["stock:read", "stock:propose"],
    });
  });

  it("gives one answer to everything that is not a valid token", async () => {
    const h = harbor();
    const token = await advisorToken(h);
    const unknown = generateToken("harbor", "pat").token;
    for (const header of [null, "", token, `Basic ${token}`, `Bearer ${token} extra`, "Bearer nonsense", bearer(unknown), bearer(generateToken("harbor", "refresh").token)]) {
      expect(await authenticate(h.guard, header)).toBeNull();
    }
  });

  it("does not query storage for text that cannot be a token", async () => {
    const h = harbor();
    let lookups = 0;
    const original = h.credentials.findByHash.bind(h.credentials);
    h.credentials.findByHash = (hash) => {
      lookups += 1;
      return original(hash);
    };
    await authenticate(h.guard, "Bearer harbor_pat_tooshort");
    await authenticate(h.guard, "Bearer other_pat_" + "a".repeat(43));
    expect(lookups).toBe(0);
  });

  it("stops working at expiry", async () => {
    const h = harbor();
    const token = await issue(h, { kind: "advisor", userId: MARA, scopes: ["orders:read"], ttlDays: 1 });
    h.advance(86_400_000 - 1);
    expect(await authenticate(h.guard, bearer(token))).not.toBeNull();
    h.advance(1);
    expect(await authenticate(h.guard, bearer(token))).toBeNull();
  });

  it("reads suspension, role and membership again on every request", async () => {
    const h = harbor();
    const owner = await issue(h, { kind: "owner", userId: NELL, tenantId: FERNHILL, scopes: ["orders:read", "stock:propose"] });
    expect((await authenticate(h.guard, bearer(owner)))!.scopes).toEqual(["orders:read", "stock:propose"]);

    // Demoted: the same token now carries read scopes only.
    h.world.setRole(NELL, FERNHILL, "viewer");
    expect((await authenticate(h.guard, bearer(owner)))!.scopes).toEqual(["orders:read"]);

    // Removed from the shop: the token is dead without anyone revoking it.
    h.world.setRole(NELL, FERNHILL, null);
    expect(await authenticate(h.guard, bearer(owner))).toBeNull();

    const advisor = await advisorToken(h);
    h.world.suspendUser(MARA);
    expect(await authenticate(h.guard, bearer(advisor))).toBeNull();
  });

  it("kills an agent token when its delegation no longer holds", async () => {
    const h = harbor();
    const agent = await agentToken(h);
    expect(await authenticate(h.guard, bearer(agent))).not.toBeNull();
    h.world.unassign(MARA, FERNHILL);
    expect(await authenticate(h.guard, bearer(agent))).toBeNull();
  });

  it("kills an agent token whose scopes were removed from the agent table", async () => {
    const h = harbor();
    const agent = await agentToken(h);
    const narrowed = harbor({ overrides: { credentials: h.credentials, agents: { restock: { scopes: ["stock:read"] } } } });
    expect(await authenticate(narrowed.guard, bearer(agent))).toBeNull();
    const gone = harbor({ overrides: { credentials: h.credentials, agents: {} } });
    expect(await authenticate(gone.guard, bearer(agent))).toBeNull();
  });

  it("refuses a token whose prefix and stored kind disagree", async () => {
    const h = harbor();
    const forged = generateToken("harbor", "pat");
    await agentToken(h);
    const row = h.credentials.rows[0]!;
    Object.assign(row, hashToken(forged.token, h.guard.pepper));
    expect(row.kind).toBe("agent");
    expect(await authenticate(h.guard, bearer(forged.token))).toBeNull();
  });

  it("upgrades an unpeppered hash after a successful request, and records use sparingly", async () => {
    const h = harbor();
    const token = await advisorToken(h);
    const row = h.credentials.rows[0]!;
    Object.assign(row, { hash: hashToken(token).hash, hashVersion: 1 });

    expect(await authenticate(h.guard, bearer(token))).not.toBeNull();
    expect(row.hashVersion).toBe(2);
    expect(row.hash).toBe(hashToken(token, h.guard.pepper).hash);

    const firstUse = row.lastUsedAt!.getTime();
    h.advance(60_000);
    await authenticate(h.guard, bearer(token));
    expect(row.lastUsedAt!.getTime()).toBe(firstUse);
    h.advance(5 * 60_000);
    await authenticate(h.guard, bearer(token));
    expect(row.lastUsedAt!.getTime()).toBeGreaterThan(firstUse);
  });

  it("does not let a housekeeping failure refuse a valid token", async () => {
    const h = harbor();
    const token = await advisorToken(h);
    h.credentials.touchLastUsed = async () => {
      throw new Error("write failed");
    };
    expect(await authenticate(h.guard, bearer(token))).not.toBeNull();
  });

  it("keeps one person's tokens out of another person's list", async () => {
    const h = harbor();
    await advisorToken(h);
    await issue(h, { kind: "owner", userId: ODILE, tenantId: LARKSPUR, scopes: ["orders:read"] });
    expect(await listCredentials(h.guard, ODILE)).toHaveLength(1);
    expect((await listCredentials(h.guard, ODILE))[0]!.tenantId).toBe(LARKSPUR);
  });
});
