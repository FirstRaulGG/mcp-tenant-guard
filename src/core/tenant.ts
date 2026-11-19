// Which tenant a call may touch.
//
// The tenant is never taken on trust from an argument, and never guessed. An advisor has to name
// it and be assigned to it; an owner or an agent is bound to one and cannot leave it.

import type { Actor, Directory, TenantRole } from "./actor.js";

/** What the tool is about to do with the tenant's data. */
export type AccessMode = "read" | "propose" | "write";

export interface Target {
  tenantId: string;
  /** The role the call runs with. An advisor or agent acts with the reach of the tenant's admin. */
  role: TenantRole;
  actingAs: Actor["kind"];
}

export type TargetDecision = { ok: true; target: Target } | { ok: false; status: 403 | 404; message: string };

export const TENANT_REQUIRED = "tenantId is required. List the tenants you can work on and pass one of their ids.";
export const TENANT_NOT_FOUND = "Tenant not found.";
export const TENANT_BOUND = "This credential is bound to one tenant and cannot act on another.";
export const AGENT_CANNOT_WRITE = "An agent credential cannot write. It can read and propose.";
export const ROLE_CANNOT_WRITE = "Your role in this tenant is read-only.";

const refuse = (status: 403 | 404, message: string): TargetDecision => ({ ok: false, status, message });

/**
 * Decides the tenant for one call.
 *
 * | Actor   | `requested`            | Result                                             |
 * | ------- | ---------------------- | -------------------------------------------------- |
 * | advisor | missing                | 403: it must be named, never guessed               |
 * | advisor | not assigned to them   | 404, the same answer as a tenant that does not exist |
 * | advisor | assigned               | the tenant, acting as its admin                    |
 * | owner   | missing or their own   | their tenant, with their current role              |
 * | owner   | another tenant         | 403. Not corrected silently: the caller is confused |
 * | agent   | missing or its own     | its tenant, read and propose only                  |
 * | agent   | another tenant         | 403                                                |
 *
 * Assignment is checked BEFORE existence, and both failures look alike, so an advisor cannot probe
 * which tenant ids exist outside their portfolio.
 */
export async function resolveTarget(
  actor: Actor,
  requested: string | null | undefined,
  mode: AccessMode,
  directory: Directory,
): Promise<TargetDecision> {
  const wanted = typeof requested === "string" ? requested.trim() : "";

  // Stated here and not only where tools are listed: a write tool reached by an agent some other
  // way must still be refused.
  if (actor.kind === "agent" && mode === "write") return refuse(403, AGENT_CANNOT_WRITE);

  if (actor.kind === "advisor") {
    if (!wanted) return refuse(403, TENANT_REQUIRED);
    if (!actor.fullPortfolio && !(await directory.isAssigned(actor.userId, wanted))) {
      return refuse(404, TENANT_NOT_FOUND);
    }
    const tenant = await directory.getTenant(wanted);
    if (!tenant || tenant.suspended) return refuse(404, TENANT_NOT_FOUND);
    return { ok: true, target: { tenantId: tenant.id, role: "admin", actingAs: "advisor" } };
  }

  if (!actor.tenantId) return refuse(403, TENANT_BOUND);
  if (wanted && wanted !== actor.tenantId) return refuse(403, TENANT_BOUND);

  if (actor.kind === "agent") {
    return { ok: true, target: { tenantId: actor.tenantId, role: "admin", actingAs: "agent" } };
  }

  const role = actor.role ?? "viewer";
  if (mode === "write" && role === "viewer") return refuse(403, ROLE_CANNOT_WRITE);
  return { ok: true, target: { tenantId: actor.tenantId, role, actingAs: "owner" } };
}
