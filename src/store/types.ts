// Storage contracts. The guard never talks to a database; it talks to these.
//
// Several methods are compare-and-swap ("only if still unused"). That is the part an adapter must
// get right: with two requests racing, exactly one of them may win. In SQL it is an UPDATE with the
// condition in its WHERE clause and a check of the affected row count.

import type { ActorKind } from "../core/actor.js";
import type { HashVersion, TokenHash } from "../core/tokens.js";

// ---------------------------------------------------------------------------
// Personal and agent tokens
// ---------------------------------------------------------------------------

export interface CredentialRecord {
  id: string;
  kind: ActorKind;
  /** The accountable person. For an agent, the advisor who delegated it. */
  userId: string;
  tenantId: string | null;
  agentName: string | null;
  /** Given by the person, to tell their tokens apart. */
  name: string;
  /** Prefix and first characters of the token. Not a secret. */
  label: string;
  scopes: string[];
  hash: string;
  hashVersion: HashVersion;
  expiresAt: Date | null;
  revokedAt: Date | null;
  lastUsedAt: Date | null;
  createdAt: Date;
}

export type RevokeResult = "revoked" | "already_revoked" | "not_found";

export interface CredentialStore {
  insert(record: CredentialRecord): Promise<void>;
  findByHash(hash: string): Promise<CredentialRecord | null>;
  /** Credentials of the user that are neither revoked nor expired. */
  countActive(userId: string, now: Date): Promise<number>;
  listByUser(userId: string): Promise<CredentialRecord[]>;
  /**
   * Revokes only if the credential belongs to `userId`. Another user's id and an id that does not
   * exist both answer `not_found`.
   */
  revoke(id: string, userId: string, at: Date): Promise<RevokeResult>;
  touchLastUsed(id: string, at: Date): Promise<void>;
  /** Replaces a hash of version `from`. A no-op if the row was already upgraded. */
  rehash(id: string, from: HashVersion, to: TokenHash): Promise<void>;
}

// ---------------------------------------------------------------------------
// OAuth
// ---------------------------------------------------------------------------

export interface OAuthClient {
  id: string;
  name: string | null;
  uri: string | null;
  redirectUris: string[];
  createdAt: Date;
}

export interface AuthorizationCode {
  id: string;
  hash: string;
  hashVersion: HashVersion;
  clientId: string;
  userId: string;
  kind: Exclude<ActorKind, "agent">;
  tenantId: string | null;
  scopes: string[];
  redirectUri: string;
  codeChallenge: string;
  resource: string;
  expiresAt: Date;
  consumedAt: Date | null;
  createdAt: Date;
}

export interface OAuthGrant {
  id: string;
  /** Shared by every token pair descended from one authorization. Revoked as a unit. */
  familyId: string;
  clientId: string;
  userId: string;
  kind: Exclude<ActorKind, "agent">;
  tenantId: string | null;
  scopes: string[];
  accessHash: string;
  refreshHash: string;
  hashVersion: HashVersion;
  expiresAt: Date;
  refreshExpiresAt: Date;
  revokedAt: Date | null;
  /** Set when the refresh token was exchanged for a new pair. Seeing it used again is a replay. */
  rotatedAt: Date | null;
  createdAt: Date;
}

export interface OAuthStore {
  insertClient(client: OAuthClient): Promise<void>;
  getClient(id: string): Promise<OAuthClient | null>;

  insertCode(code: AuthorizationCode): Promise<void>;
  findCodeByHash(hash: string): Promise<AuthorizationCode | null>;
  /** Marks the code used. False if it was already used: exactly one caller may get true. */
  consumeCode(id: string, at: Date): Promise<boolean>;

  insertGrant(grant: OAuthGrant): Promise<void>;
  findGrantByAccessHash(hash: string): Promise<OAuthGrant | null>;
  findGrantByRefreshHash(hash: string): Promise<OAuthGrant | null>;
  /** Marks the grant rotated and revoked, only if it is neither. Exactly one caller may get true. */
  rotateGrant(id: string, at: Date): Promise<boolean>;
  /** Revokes every live grant of the family. Returns how many. */
  revokeFamily(familyId: string, at: Date): Promise<number>;
  /** Live and past connections of a user, newest first. */
  listGrants(userId: string): Promise<OAuthGrant[]>;
  /** Same contract as `CredentialStore.revoke`. */
  revokeGrant(id: string, userId: string, at: Date): Promise<RevokeResult>;
}

// ---------------------------------------------------------------------------
// Agent runs
// ---------------------------------------------------------------------------

export type RunStatus = "running" | "done" | "failed";

export interface AgentRun {
  id: string;
  credentialId: string;
  userId: string;
  tenantId: string;
  agentName: string;
  trigger: string;
  /** Chosen by the caller. Unique per credential: repeating it returns the same run. */
  clientRequestId: string;
  status: RunStatus;
  summary: string | null;
  startedAt: Date;
  endedAt: Date | null;
}

export interface RunStore {
  /**
   * Inserts the run unless one with the same credential and `clientRequestId` exists, and returns
   * whichever is stored. Two racing calls get the same run.
   */
  insertOrGet(run: AgentRun): Promise<{ run: AgentRun; created: boolean }>;
  get(id: string): Promise<AgentRun | null>;
  /** The most recent running run of the credential. */
  findRunning(credentialId: string): Promise<AgentRun | null>;
  /** Marks as failed every other running run of the same credential and agent. */
  supersede(credentialId: string, agentName: string, exceptId: string, at: Date): Promise<void>;
  /** Closes the run only if it is still running. False if it was already closed. */
  close(id: string, result: { status: "done" | "failed"; summary: string | null; at: Date }): Promise<boolean>;
}
