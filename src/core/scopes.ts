// Scopes: what a credential may do, by area and by nature.
//
// Scopes are independent. Holding "orders:read" says nothing about "customers:read": if one implied
// the other, adding a tool tomorrow would quietly widen every token issued yesterday.

export type ScopeNature = "read" | "propose" | "write";

export interface ScopeCatalog {
  /** Every known scope, in display order. */
  readonly all: readonly string[];
  natureOf(scope: string): ScopeNature | null;
  /** Scopes that are also satisfied by holding `scope`. One direction only. */
  impliedBy(scope: string): readonly string[];
}

export interface ScopeDefinition {
  read?: readonly string[];
  /** Asks a person to do something. Never changes state by itself. */
  propose?: readonly string[];
  write?: readonly string[];
  /**
   * `{ "notes:write": ["notes:read"] }`: holding the key also satisfies the listed scopes. Meant
   * for keeping old tokens working after a scope is split, not as a general hierarchy.
   */
  implies?: Readonly<Record<string, readonly string[]>>;
}

export function defineScopes(definition: ScopeDefinition): ScopeCatalog {
  const nature = new Map<string, ScopeNature>();
  for (const key of ["read", "propose", "write"] as const) {
    for (const scope of definition[key] ?? []) {
      if (!/^[a-z][a-z0-9_.-]*:[a-z][a-z0-9_-]*$/.test(scope)) throw new Error(`invalid scope name: ${scope}`);
      if (nature.has(scope)) throw new Error(`scope declared twice: ${scope}`);
      nature.set(scope, key);
    }
  }
  if (nature.size === 0) throw new Error("a scope catalog needs at least one scope");

  const implies = new Map<string, readonly string[]>();
  for (const [holder, satisfied] of Object.entries(definition.implies ?? {})) {
    for (const scope of [holder, ...satisfied]) {
      if (!nature.has(scope)) throw new Error(`implies refers to an unknown scope: ${scope}`);
    }
    implies.set(holder, satisfied);
  }

  return {
    all: [...nature.keys()],
    natureOf: (scope) => nature.get(scope) ?? null,
    impliedBy: (scope) => implies.get(scope) ?? [],
  };
}

/**
 * Keeps only known scopes, once each, in catalog order. Applied to stored scopes on EVERY read, so
 * a scope removed from the catalog stops working on tokens that still list it.
 */
export function parseScopes(catalog: ScopeCatalog, raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const wanted = new Set(raw.filter((item): item is string => typeof item === "string"));
  return catalog.all.filter((scope) => wanted.has(scope));
}

export function hasScope(catalog: ScopeCatalog, granted: readonly string[], needed: string): boolean {
  return granted.some((scope) => scope === needed || catalog.impliedBy(scope).includes(needed));
}

export function scopesOfNature(catalog: ScopeCatalog, scopes: readonly string[], ...natures: ScopeNature[]): string[] {
  return scopes.filter((scope) => {
    const nature = catalog.natureOf(scope);
    return nature !== null && natures.includes(nature);
  });
}

/**
 * True when one credential would both READ text written by outsiders and CHANGE state.
 *
 * That pairing is the one that turns a prompt injection into an action: an instruction hidden in
 * an order note is read with the same token that could then obey it. The rule is about the nature
 * of the scopes, not how many there are: two read scopes are fine, a write scope alone is fine.
 * Proposals do not count as a change, because a person decides each one.
 */
export function mixesReadAndWrite(catalog: ScopeCatalog, scopes: readonly string[]): boolean {
  return (
    scopesOfNature(catalog, scopes, "write").length > 0 &&
    scopesOfNature(catalog, scopes, "read").length > 0
  );
}
