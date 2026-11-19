// Who is on the other end of a tool call.

/**
 * - `advisor`: a staff user who works across the tenants assigned to them. Must name the tenant on
 *   every call.
 * - `owner`: a member of one tenant, bound to it. The role is read again on every request.
 * - `agent`: an unattended process delegated by an advisor to one tenant. Reads and proposes;
 *   never writes.
 */
export type ActorKind = "advisor" | "owner" | "agent";

export const ACTOR_KINDS: readonly ActorKind[] = ["advisor", "owner", "agent"];

export type TenantRole = "admin" | "member" | "viewer";

export interface Actor {
  kind: ActorKind;
  /** Id of the credential row. Safe to log; it is not the secret. */
  credentialId: string;
  credential: "pat" | "oauth";
  /** The accountable person. For an agent this is the advisor who delegated it. */
  userId: string;
  /** Effective scopes for THIS request, after the role and the agent allowlist were applied. */
  scopes: readonly string[];
  /** The one tenant an owner or agent is bound to. Null for an advisor. */
  tenantId: string | null;
  /** An owner's current role in its tenant. Null otherwise. */
  role: TenantRole | null;
  agentName: string | null;
  /** An advisor who is not limited to assigned tenants. Never true for another kind. */
  fullPortfolio: boolean;
}

/** The directory of the host application: users, tenants and who may work on what. */
export interface Directory {
  getUser(userId: string): Promise<DirectoryUser | null>;
  getTenant(tenantId: string): Promise<DirectoryTenant | null>;
  /** The user's role in the tenant, or null when they are not a member. */
  getMembership(userId: string, tenantId: string): Promise<TenantRole | null>;
  /** Whether the advisor is assigned to the tenant. Not consulted for a full-portfolio advisor. */
  isAssigned(advisorId: string, tenantId: string): Promise<boolean>;
}

export interface DirectoryUser {
  id: string;
  suspended: boolean;
  /** `advisor` works on assigned tenants, `admin` on all of them, null is not staff. */
  staff: "advisor" | "admin" | null;
}

export interface DirectoryTenant {
  id: string;
  suspended: boolean;
}
