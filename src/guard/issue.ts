// Issuing, listing and revoking personal and agent tokens.
//
// These functions assume the caller already knows who is asking, from the host application's own
// session. A token must never be accepted as proof of identity here: a credential that can mint
// credentials cannot be contained.

import type { ActorKind } from "../core/actor.js";
import { mixesReadAndWrite, parseScopes, scopesOfNature } from "../core/scopes.js";
import { expiryFor, generateToken, hashToken, tokenUsability } from "../core/tokens.js";
import type { CredentialRecord, RevokeResult } from "../store/types.js";
import type { Guard } from "./guard.js";

export interface IssueRequest {
  kind: ActorKind;
  /** The signed-in person asking. For an agent credential, the advisor delegating it. */
  userId: string;
  /** Required for `owner` and `agent`. Must be absent for `advisor`. */
  tenantId?: string | null;
  /** Required for `agent`: a name from the guard's agent table. */
  agentName?: string | null;
  name: string;
  /** Ignored for an agent, whose scopes come from the agent table and nowhere else. */
  scopes?: readonly string[];
  ttlDays?: number;
  /** Must be true to issue one token that both reads outside text and writes. */
  confirmReadAndWrite?: boolean;
}

export type IssueFailure =
  | "invalid_name"
  | "invalid_ttl"
  | "invalid_scopes"
  | "read_and_write_needs_confirmation"
  | "not_allowed"
  | "too_many_credentials";

export type IssueResult =
  | { ok: true; token: string; credential: CredentialSummary }
  | { ok: false; reason: IssueFailure; message: string };

/** What a person may see about a credential. Never the hash. */
export interface CredentialSummary {
  id: string;
  kind: ActorKind;
  name: string;
  label: string;
  tenantId: string | null;
  agentName: string | null;
  scopes: string[];
  status: "active" | "revoked" | "expired";
  expiresAt: Date | null;
  lastUsedAt: Date | null;
  createdAt: Date;
}

const fail = (reason: IssueFailure, message: string): IssueResult => ({ ok: false, reason, message });

export function summarize(record: CredentialRecord, now: Date): CredentialSummary {
  const usability = tokenUsability(record, now);
  return {
    id: record.id,
    kind: record.kind,
    name: record.name,
    label: record.label,
    tenantId: record.tenantId,
    agentName: record.agentName,
    scopes: [...record.scopes],
    status: usability === "ok" ? "active" : usability,
    expiresAt: record.expiresAt,
    lastUsedAt: record.lastUsedAt,
    createdAt: record.createdAt,
  };
}

export async function issueCredential(guard: Guard, request: IssueRequest): Promise<IssueResult> {
  const now = guard.now();
  const name = request.name.trim();
  if (!name || name.length > 100) return fail("invalid_name", "Give the token a name of up to 100 characters.");

  const expiresAt = expiryFor(request.ttlDays, now);
  if (!expiresAt) return fail("invalid_ttl", "A token lasts between 1 and 365 days.");

  const user = await guard.directory.getUser(request.userId);
  if (!user || user.suspended) return fail("not_allowed", "This account cannot issue tokens.");

  let scopes: string[];
  let tenantId: string | null = null;
  let agentName: string | null = null;

  if (request.kind === "advisor") {
    if (!user.staff || request.tenantId) return fail("not_allowed", "This account cannot issue this kind of token.");
    scopes = parseScopes(guard.scopes, request.scopes);
  } else {
    const tenant = request.tenantId ? await guard.directory.getTenant(request.tenantId) : null;
    if (!tenant || tenant.suspended) return fail("not_allowed", "This account cannot issue a token for that tenant.");
    tenantId = tenant.id;

    if (request.kind === "owner") {
      const role = await guard.directory.getMembership(user.id, tenant.id);
      if (!role) return fail("not_allowed", "This account cannot issue a token for that tenant.");
      scopes = parseScopes(guard.scopes, request.scopes);
      // A viewer cannot mint what a viewer cannot do.
      if (role === "viewer" && scopesOfNature(guard.scopes, scopes, "write", "propose").length > 0) {
        return fail("invalid_scopes", "Your role in this tenant allows read scopes only.");
      }
    } else {
      const definition = request.agentName ? guard.agents[request.agentName] : undefined;
      if (!request.agentName || !definition) return fail("not_allowed", "Unknown agent.");
      if (!user.staff) return fail("not_allowed", "Only staff can delegate an agent.");
      if (user.staff !== "admin" && !(await guard.directory.isAssigned(user.id, tenant.id))) {
        return fail("not_allowed", "This account cannot issue a token for that tenant.");
      }
      agentName = request.agentName;
      // From the table, never from the request body.
      scopes = parseScopes(guard.scopes, definition.scopes);
    }
  }

  if (scopes.length === 0 || (request.kind !== "agent" && scopes.length !== (request.scopes?.length ?? 0))) {
    return fail("invalid_scopes", "Choose at least one scope, and only scopes that exist.");
  }
  if (mixesReadAndWrite(guard.scopes, scopes) && request.confirmReadAndWrite !== true) {
    return fail(
      "read_and_write_needs_confirmation",
      "This token would both read text written by outsiders and change data. An instruction hidden in that text could be carried out with it. Confirm to issue it anyway, or issue two tokens.",
    );
  }

  if ((await guard.credentials.countActive(user.id, now)) >= guard.maxActiveCredentialsPerUser) {
    return fail("too_many_credentials", `You already have ${guard.maxActiveCredentialsPerUser} active tokens. Revoke one first.`);
  }

  const issued = generateToken(guard.brand, request.kind === "agent" ? "agent" : "pat");
  const hashed = hashToken(issued.token, guard.pepper);
  const record: CredentialRecord = {
    id: guard.newId(),
    kind: request.kind,
    userId: user.id,
    tenantId,
    agentName,
    name,
    label: issued.label,
    scopes,
    hash: hashed.hash,
    hashVersion: hashed.version,
    expiresAt,
    revokedAt: null,
    lastUsedAt: null,
    createdAt: now,
  };
  await guard.credentials.insert(record);
  return { ok: true, token: issued.token, credential: summarize(record, now) };
}

export async function listCredentials(guard: Guard, userId: string): Promise<CredentialSummary[]> {
  const now = guard.now();
  return (await guard.credentials.listByUser(userId)).map((record) => summarize(record, now));
}

/** Another user's credential and one that does not exist both answer `not_found`. */
export function revokeCredential(guard: Guard, userId: string, credentialId: string): Promise<RevokeResult> {
  return guard.credentials.revoke(credentialId, userId, guard.now());
}
