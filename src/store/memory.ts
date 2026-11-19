// In-memory adapters. They back the tests and the example server, and they are the reference for
// what a real adapter has to do. Nothing here survives a restart.

import type { AuditEntry, AuditStore, NewAuditEntry } from "../core/audit.js";
import type { HashVersion, TokenHash } from "../core/tokens.js";
import { tokenUsability } from "../core/tokens.js";
import type {
  AgentRun,
  AuthorizationCode,
  CredentialRecord,
  CredentialStore,
  OAuthClient,
  OAuthGrant,
  OAuthStore,
  RevokeResult,
  RunStore,
} from "./types.js";

export class MemoryCredentialStore implements CredentialStore {
  readonly rows: CredentialRecord[] = [];

  async insert(record: CredentialRecord): Promise<void> {
    this.rows.push({ ...record, scopes: [...record.scopes] });
  }

  async findByHash(hash: string): Promise<CredentialRecord | null> {
    const row = this.rows.find((r) => r.hash === hash);
    return row ? { ...row, scopes: [...row.scopes] } : null;
  }

  async countActive(userId: string, now: Date): Promise<number> {
    return this.rows.filter((r) => r.userId === userId && tokenUsability(r, now) === "ok").length;
  }

  async listByUser(userId: string): Promise<CredentialRecord[]> {
    return this.rows
      .filter((r) => r.userId === userId)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
      .map((r) => ({ ...r, scopes: [...r.scopes] }));
  }

  async revoke(id: string, userId: string, at: Date): Promise<RevokeResult> {
    const row = this.rows.find((r) => r.id === id && r.userId === userId);
    if (!row) return "not_found";
    if (row.revokedAt) return "already_revoked";
    row.revokedAt = at;
    return "revoked";
  }

  async touchLastUsed(id: string, at: Date): Promise<void> {
    const row = this.rows.find((r) => r.id === id);
    if (row) row.lastUsedAt = at;
  }

  async rehash(id: string, from: HashVersion, to: TokenHash): Promise<void> {
    const row = this.rows.find((r) => r.id === id && r.hashVersion === from);
    if (!row) return;
    row.hash = to.hash;
    row.hashVersion = to.version;
  }
}

export class MemoryOAuthStore implements OAuthStore {
  readonly clients: OAuthClient[] = [];
  readonly codes: AuthorizationCode[] = [];
  readonly grants: OAuthGrant[] = [];

  async insertClient(client: OAuthClient): Promise<void> {
    this.clients.push({ ...client, redirectUris: [...client.redirectUris] });
  }

  async getClient(id: string): Promise<OAuthClient | null> {
    return this.clients.find((c) => c.id === id) ?? null;
  }

  async insertCode(code: AuthorizationCode): Promise<void> {
    this.codes.push({ ...code });
  }

  async findCodeByHash(hash: string): Promise<AuthorizationCode | null> {
    const code = this.codes.find((c) => c.hash === hash);
    return code ? { ...code } : null;
  }

  async consumeCode(id: string, at: Date): Promise<boolean> {
    const code = this.codes.find((c) => c.id === id);
    if (!code || code.consumedAt) return false;
    code.consumedAt = at;
    return true;
  }

  async insertGrant(grant: OAuthGrant): Promise<void> {
    this.grants.push({ ...grant, scopes: [...grant.scopes] });
  }

  async findGrantByAccessHash(hash: string): Promise<OAuthGrant | null> {
    const grant = this.grants.find((g) => g.accessHash === hash);
    return grant ? { ...grant } : null;
  }

  async findGrantByRefreshHash(hash: string): Promise<OAuthGrant | null> {
    const grant = this.grants.find((g) => g.refreshHash === hash);
    return grant ? { ...grant } : null;
  }

  async rotateGrant(id: string, at: Date): Promise<boolean> {
    const grant = this.grants.find((g) => g.id === id);
    if (!grant || grant.revokedAt || grant.rotatedAt) return false;
    grant.rotatedAt = at;
    grant.revokedAt = at;
    return true;
  }

  async revokeFamily(familyId: string, at: Date): Promise<number> {
    let revoked = 0;
    for (const grant of this.grants) {
      if (grant.familyId !== familyId || grant.revokedAt) continue;
      grant.revokedAt = at;
      revoked += 1;
    }
    return revoked;
  }

  async listGrants(userId: string): Promise<OAuthGrant[]> {
    return this.grants
      .filter((g) => g.userId === userId)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
      .map((g) => ({ ...g }));
  }

  async revokeGrant(id: string, userId: string, at: Date): Promise<RevokeResult> {
    const grant = this.grants.find((g) => g.id === id && g.userId === userId);
    if (!grant) return "not_found";
    if (grant.revokedAt) return "already_revoked";
    grant.revokedAt = at;
    return "revoked";
  }
}

export class MemoryAuditStore implements AuditStore {
  readonly entries: AuditEntry[] = [];
  /** Set to make `open` throw, to exercise the fail-closed path. */
  failOpen = false;
  /** Set to make `close` throw, to exercise the best-effort path. */
  failClose = false;
  private sequence = 0;

  async open(entry: NewAuditEntry): Promise<string> {
    if (this.failOpen) throw new Error("audit store unavailable");
    const id = `audit_${(this.sequence += 1)}`;
    this.entries.push({ ...entry, id, outcome: "open", status: null, durationMs: null });
    return id;
  }

  async close(id: string, result: { outcome: "ok" | "error"; status: number; durationMs: number }): Promise<void> {
    if (this.failClose) throw new Error("audit store unavailable");
    const entry = this.entries.find((e) => e.id === id);
    if (entry) Object.assign(entry, result);
  }

  async denied(entry: NewAuditEntry & { status: number }): Promise<void> {
    if (this.failOpen) throw new Error("audit store unavailable");
    const id = `audit_${(this.sequence += 1)}`;
    this.entries.push({ ...entry, id, outcome: "denied", durationMs: 0 });
  }
}

export class MemoryRunStore implements RunStore {
  readonly runs: AgentRun[] = [];

  async insertOrGet(run: AgentRun): Promise<{ run: AgentRun; created: boolean }> {
    const existing = this.runs.find(
      (r) => r.credentialId === run.credentialId && r.clientRequestId === run.clientRequestId,
    );
    if (existing) return { run: { ...existing }, created: false };
    this.runs.push({ ...run });
    return { run: { ...run }, created: true };
  }

  async get(id: string): Promise<AgentRun | null> {
    const run = this.runs.find((r) => r.id === id);
    return run ? { ...run } : null;
  }

  async findRunning(credentialId: string): Promise<AgentRun | null> {
    const running = this.runs
      .filter((r) => r.credentialId === credentialId && r.status === "running")
      .sort((a, b) => b.startedAt.getTime() - a.startedAt.getTime());
    return running[0] ? { ...running[0] } : null;
  }

  async supersede(credentialId: string, agentName: string, exceptId: string, at: Date): Promise<void> {
    for (const run of this.runs) {
      if (run.credentialId !== credentialId || run.agentName !== agentName) continue;
      if (run.id === exceptId || run.status !== "running") continue;
      run.status = "failed";
      run.summary = "superseded by a newer run";
      run.endedAt = at;
    }
  }

  async close(id: string, result: { status: "done" | "failed"; summary: string | null; at: Date }): Promise<boolean> {
    const run = this.runs.find((r) => r.id === id);
    if (!run || run.status !== "running") return false;
    run.status = result.status;
    run.summary = result.summary;
    run.endedAt = result.at;
    return true;
  }
}
