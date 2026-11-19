// The record of who read or changed what.

import type { ActorKind } from "./actor.js";

export type AuditOutcome = "open" | "ok" | "error" | "denied";

export interface AuditEntry {
  id: string;
  at: Date;
  credentialId: string;
  /** The accountable person: for an agent, the advisor who delegated it. */
  userId: string;
  actorKind: ActorKind;
  agentName: string | null;
  /** The tenant the call was resolved to. For a denied call, the tenant that was asked for. */
  tenantId: string | null;
  tool: string;
  /** Only the arguments the tool declared as loggable. Never the result. */
  params: Record<string, unknown>;
  traceId: string;
  runId: string | null;
  /** `open` means the call started and never reported back: a crash, or a failed update. */
  outcome: AuditOutcome;
  status: number | null;
  durationMs: number | null;
}

export type NewAuditEntry = Omit<AuditEntry, "id" | "outcome" | "status" | "durationMs">;

/**
 * Rows carry no foreign key to credentials or users on purpose: revoking a token or deleting a
 * user must not erase what they did.
 */
export interface AuditStore {
  /** Records that a call is about to run. If this throws, the call does not run. */
  open(entry: NewAuditEntry): Promise<string>;
  close(id: string, result: { outcome: "ok" | "error"; status: number; durationMs: number }): Promise<void>;
  /** Records a call refused before it ran (missing scope, wrong tenant). */
  denied(entry: NewAuditEntry & { status: number }): Promise<void>;
}

export const MAX_AUDIT_PARAMS_BYTES = 2048;
export const MAX_AUDIT_VALUE_BYTES = 256;

function serializedBytes(value: unknown): number {
  try {
    return Buffer.byteLength(JSON.stringify(value) ?? "", "utf8");
  } catch {
    return -1;
  }
}

/**
 * Parameters as they will be stored. Each value is judged alone: one that is oversized or cannot
 * be serialized is replaced by a marker and the others are kept, so a caller cannot blank out the
 * record ids of a call by padding another argument. This never throws, because an audit trail that
 * fails on odd input stops calls for no reason.
 */
export function auditParams(params: Record<string, unknown>): Record<string, unknown> {
  const stored: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(params)) {
    const bytes = serializedBytes(value);
    stored[key] = bytes < 0 || bytes > MAX_AUDIT_VALUE_BYTES ? { _truncated: true, bytes } : value;
  }
  const total = serializedBytes(stored);
  return total > MAX_AUDIT_PARAMS_BYTES ? { _truncated: true, bytes: total } : stored;
}

/** Picks the arguments a tool declared as loggable. Free text is logged only if the tool says so. */
export function pickLoggable(args: Record<string, unknown>, loggable: readonly string[]): Record<string, unknown> {
  const picked: Record<string, unknown> = {};
  for (const key of loggable) {
    const value = args[key];
    if (value !== undefined) picked[key] = value;
  }
  return picked;
}
