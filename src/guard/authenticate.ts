// From an `Authorization` header to an actor, or to nothing.
//
// Two rules shape this file.
//
// One answer for every failure. A missing header, a malformed token, an unknown one, a revoked one,
// a suspended owner, a switched-off feature: the caller sees the same refusal for all of them. A
// different message for "this token existed" is a tool for someone holding a stolen list.
//
// Nothing is trusted from the day of issue. Role, membership, suspension, assignment and the
// agent's allowlist are all read again on every request, so taking a permission away works on
// credentials that are already out there, without hunting them down.

import type { Actor } from "../core/actor.js";
import { parseScopes, scopesOfNature } from "../core/scopes.js";
import { candidateHashes, classifyToken, hashToken, shouldTouchLastUsed, tokenUsability } from "../core/tokens.js";
import type { Guard } from "./guard.js";

// The scheme name is case-insensitive (RFC 9110).
const BEARER = /^Bearer ([^\s]+)$/i;

export function bearerToken(header: string | null | undefined): string | null {
  return header ? (BEARER.exec(header.trim())?.[1] ?? null) : null;
}

/** The actor behind the header, or null. Null always means the same 401. */
export async function authenticate(guard: Guard, authorization: string | null | undefined): Promise<Actor | null> {
  const token = bearerToken(authorization);
  if (!token) return null;

  const tokenClass = classifyToken(guard.brand, token);
  if (tokenClass === "pat" || tokenClass === "agent") return authenticateCredential(guard, token, tokenClass);
  if (tokenClass === "access") return authenticateAccessToken(guard, token);
  // A refresh token is never a way in.
  return null;
}

async function authenticateCredential(guard: Guard, token: string, tokenClass: "pat" | "agent"): Promise<Actor | null> {
  // With no agent registered there is nothing an agent token could be. Decided before any lookup.
  if (tokenClass === "agent" && Object.keys(guard.agents).length === 0) return null;

  let record = null;
  for (const candidate of candidateHashes(token, guard.pepper)) {
    record = await guard.credentials.findByHash(candidate.hash);
    if (record) break;
  }
  if (!record) return null;

  const now = guard.now();
  if (tokenUsability(record, now) !== "ok") return null;
  // The prefix and the stored kind must agree: an agent row presented as a personal token, or the
  // reverse, is refused.
  if ((record.kind === "agent") !== (tokenClass === "agent")) return null;

  const actor = await deriveActor(guard, {
    kind: record.kind,
    credentialId: record.id,
    credential: "pat",
    userId: record.userId,
    tenantId: record.tenantId,
    agentName: record.agentName,
    storedScopes: record.scopes,
  });
  if (!actor) return null;

  // Housekeeping, only after the request was accepted. Neither step may fail the request.
  try {
    if (guard.pepper && record.hashVersion === 1) {
      await guard.credentials.rehash(record.id, 1, hashToken(token, guard.pepper));
    }
    if (shouldTouchLastUsed(record.lastUsedAt, now)) await guard.credentials.touchLastUsed(record.id, now);
  } catch (err) {
    guard.emit({ type: "housekeeping_failed", message: "credential housekeeping failed", detail: { error: String(err) } });
  }
  return actor;
}

async function authenticateAccessToken(guard: Guard, token: string): Promise<Actor | null> {
  // Checked BEFORE the lookup: with OAuth off, an access token costs no query and gets the same
  // refusal as a random string.
  if (!guard.oauth || !guard.oauthEnabled()) return null;

  let grant = null;
  for (const candidate of candidateHashes(token, guard.pepper)) {
    grant = await guard.oauth.store.findGrantByAccessHash(candidate.hash);
    if (grant) break;
  }
  if (!grant) return null;
  if (tokenUsability(grant, guard.now()) !== "ok") return null;

  return deriveActor(guard, {
    kind: grant.kind,
    credentialId: grant.id,
    credential: "oauth",
    userId: grant.userId,
    tenantId: grant.tenantId,
    agentName: null,
    storedScopes: grant.scopes,
  });
}

interface StoredIdentity {
  kind: Actor["kind"];
  credentialId: string;
  credential: Actor["credential"];
  userId: string;
  tenantId: string | null;
  agentName: string | null;
  storedScopes: readonly string[];
}

/** Re-derives what the credential may do right now. Null when it may do nothing. */
async function deriveActor(guard: Guard, stored: StoredIdentity): Promise<Actor | null> {
  const { directory } = guard;
  const user = await directory.getUser(stored.userId);
  if (!user || user.suspended) return null;

  const scopes = parseScopes(guard.scopes, stored.storedScopes);
  const base = {
    credentialId: stored.credentialId,
    credential: stored.credential,
    userId: user.id,
  };

  if (stored.kind === "advisor") {
    if (!user.staff) return null;
    if (stored.tenantId !== null) return null;
    return { ...base, kind: "advisor", scopes, tenantId: null, role: null, agentName: null, fullPortfolio: user.staff === "admin" };
  }

  if (!stored.tenantId) return null;
  const tenant = await directory.getTenant(stored.tenantId);
  if (!tenant || tenant.suspended) return null;

  if (stored.kind === "owner") {
    const role = await directory.getMembership(user.id, tenant.id);
    if (!role) return null;
    // A viewer keeps only read scopes, whatever the token was issued with. A demotion takes effect
    // on the next request.
    const effective = role === "viewer" ? scopesOfNature(guard.scopes, scopes, "read") : scopes;
    return { ...base, kind: "owner", scopes: effective, tenantId: tenant.id, role, agentName: null, fullPortfolio: false };
  }

  // Agent. Every condition of the delegation must still hold.
  const definition = stored.agentName ? guard.agents[stored.agentName] : undefined;
  if (!stored.agentName || !definition) return null;
  // A stored scope outside the allowlist means the allowlist shrank after issue: the credential is
  // dead as a whole, not quietly narrowed.
  if (scopes.length !== stored.storedScopes.length) return null;
  if (!scopes.every((scope) => definition.scopes.includes(scope))) return null;
  if (scopesOfNature(guard.scopes, scopes, "write").length > 0) return null;
  // The delegator must still be staff and still be allowed on this tenant.
  if (!user.staff) return null;
  if (user.staff !== "admin" && !(await directory.isAssigned(user.id, tenant.id))) return null;

  return { ...base, kind: "agent", scopes, tenantId: tenant.id, role: null, agentName: stored.agentName, fullPortfolio: false };
}
