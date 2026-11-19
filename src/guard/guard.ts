// The guard: one object holding everything a request is checked against.

import { randomUUID } from "node:crypto";

import type { Directory } from "../core/actor.js";
import type { AuditStore } from "../core/audit.js";
import { DEFAULT_LIMITS, MemoryRateLimiter } from "../core/limits.js";
import type { GuardLimits, RateLimiter } from "../core/limits.js";
import { DEFAULT_MAX_RESULT_BYTES } from "../core/result.js";
import type { SanitizeOptions } from "../core/sanitize.js";
import type { ScopeCatalog } from "../core/scopes.js";
import { assertBrand } from "../core/tokens.js";
import type { RedirectPolicy } from "../oauth/redirects.js";
import type { CredentialStore, OAuthStore, RunStore } from "../store/types.js";

export interface AgentDefinition {
  /** The most this agent may ever hold. Read and propose scopes only. */
  scopes: readonly string[];
}

export interface OAuthConfig {
  store: OAuthStore;
  /** The authorization server's origin, for example `https://app.example.test`. No trailing slash. */
  issuer: string;
  /** The one URL access tokens are valid for: the MCP endpoint. */
  resource: string;
  redirects: RedirectPolicy;
  /** Lifetime of an access token. Default: one hour. */
  accessTtlSeconds?: number;
  /** Lifetime of a refresh token, renewed on each rotation. Default: 90 days. */
  refreshTtlSeconds?: number;
  /**
   * Checked on every request. When it returns false, sign-in stops AND access tokens that were
   * already issued stop working: it is a switch for the whole feature, not just for new logins.
   */
  enabled?: () => boolean;
}

export interface GuardEvent {
  type:
    | "tool"
    | "unauthorized"
    | "rate_limited"
    | "refused"
    | "internal_error"
    | "housekeeping_failed"
    | "audit_close_failed"
    | "audit_denied_failed"
    | "config_warning";
  traceId?: string;
  message?: string;
  detail?: Record<string, unknown>;
}

export interface GuardConfig {
  /** Short prefix of every token, for example `acme`. Makes a leaked token attributable. */
  brand: string;
  scopes: ScopeCatalog;
  directory: Directory;
  credentials: CredentialStore;
  audit: AuditStore;
  /**
   * Server-side secret mixed into token hashes. Required, unless `allowUnpepperedHashes` is set:
   * running without one should be a decision somebody made, not a missing variable.
   */
  pepper?: string;
  allowUnpepperedHashes?: boolean;
  /** Agents that may hold credentials, by name. Empty or absent means no agent can authenticate. */
  agents?: Readonly<Record<string, AgentDefinition>>;
  oauth?: OAuthConfig;
  runs?: RunStore;
  limiter?: RateLimiter;
  limits?: Partial<GuardLimits>;
  /** Applied to every string in every tool result. */
  sanitize?: SanitizeOptions;
  maxResultBytes?: number;
  /** Time one HTTP request may spend in tools, across all calls batched in it. */
  toolBudgetMs?: number;
  maxActiveCredentialsPerUser?: number;
  now?: () => Date;
  newId?: () => string;
  /**
   * Receives structured events. They never carry tool arguments, results or tokens. An
   * `internal_error` carries the message of the error that was thrown, which is whatever your own
   * code or driver put in it: treat this stream as an operator log, not as something to show users.
   */
  onEvent?: (event: GuardEvent) => void;
}

export interface Guard {
  readonly brand: string;
  readonly scopes: ScopeCatalog;
  readonly directory: Directory;
  readonly credentials: CredentialStore;
  readonly audit: AuditStore;
  readonly pepper: string | null;
  readonly agents: Readonly<Record<string, AgentDefinition>>;
  readonly oauth: OAuthConfig | null;
  readonly runs: RunStore | null;
  readonly limiter: RateLimiter;
  readonly limits: GuardLimits;
  readonly sanitize: SanitizeOptions;
  readonly maxResultBytes: number;
  readonly toolBudgetMs: number;
  readonly maxActiveCredentialsPerUser: number;
  now(): Date;
  newId(): string;
  emit(event: GuardEvent): void;
  oauthEnabled(): boolean;
}

export function createGuard(config: GuardConfig): Guard {
  assertBrand(config.brand);

  const pepper = config.pepper?.trim() || null;
  if (!pepper && !config.allowUnpepperedHashes) {
    throw new Error("a pepper is required. Pass `pepper`, or set `allowUnpepperedHashes` to run without one on purpose.");
  }
  if (pepper && pepper.length < 32) throw new Error("the pepper must be at least 32 characters");

  const agents = config.agents ?? {};
  for (const [name, definition] of Object.entries(agents)) {
    if (!/^[a-z][a-z0-9_-]{1,39}$/.test(name)) throw new Error(`invalid agent name: ${name}`);
    for (const scope of definition.scopes) {
      const nature = config.scopes.natureOf(scope);
      if (!nature) throw new Error(`agent ${name} lists an unknown scope: ${scope}`);
      // Refused when the server starts, so that no later edit of the table can hand an unattended
      // process a write scope.
      if (nature === "write") throw new Error(`agent ${name} may not hold a write scope: ${scope}`);
    }
  }

  if (config.oauth) {
    for (const [name, value] of [["issuer", config.oauth.issuer], ["resource", config.oauth.resource]] as const) {
      let url: URL;
      try {
        url = new URL(value);
      } catch {
        throw new Error(`oauth.${name} must be an absolute URL`);
      }
      const local = url.hostname === "localhost" || url.hostname === "127.0.0.1";
      if (url.protocol !== "https:" && !local) throw new Error(`oauth.${name} must use https`);
      if (url.hash || url.search) throw new Error(`oauth.${name} must not have a query or a fragment`);
    }
    if (config.oauth.issuer.endsWith("/")) throw new Error("oauth.issuer must not end with a slash");
  }

  const now = config.now ?? (() => new Date());
  const emit = config.onEvent ?? (() => {});

  return {
    brand: config.brand,
    scopes: config.scopes,
    directory: config.directory,
    credentials: config.credentials,
    audit: config.audit,
    pepper,
    agents,
    oauth: config.oauth ?? null,
    runs: config.runs ?? null,
    limiter: config.limiter ?? new MemoryRateLimiter(() => now().getTime()),
    limits: { ...DEFAULT_LIMITS, ...config.limits },
    sanitize: config.sanitize ?? {},
    maxResultBytes: config.maxResultBytes ?? DEFAULT_MAX_RESULT_BYTES,
    toolBudgetMs: config.toolBudgetMs ?? 50_000,
    maxActiveCredentialsPerUser: config.maxActiveCredentialsPerUser ?? 20,
    now,
    newId: config.newId ?? randomUUID,
    emit: (event) => {
      try {
        emit(event);
      } catch {
        // A broken logger must not break a request.
      }
    },
    oauthEnabled: () => !!config.oauth && (config.oauth.enabled?.() ?? true),
  };
}
