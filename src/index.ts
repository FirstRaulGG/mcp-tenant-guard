export type { Actor, ActorKind, Directory, DirectoryTenant, DirectoryUser, TenantRole } from "./core/actor.js";
export { ACTOR_KINDS } from "./core/actor.js";
export { MAX_AUDIT_PARAMS_BYTES, auditParams, pickLoggable } from "./core/audit.js";
export type { AuditEntry, AuditOutcome, AuditStore, NewAuditEntry } from "./core/audit.js";
export { DEFAULT_LIMITS, MemoryRateLimiter } from "./core/limits.js";
export type { GuardLimits, LimitCharge, LimitDecision, LimitRule, RateLimiter } from "./core/limits.js";
export {
  DEFAULT_MAX_RESULT_BYTES,
  TOOL_HINTS,
  TOOL_STATUSES,
  ToolError,
  enforceResultSize,
  errorResult,
  okResult,
  statusOf,
} from "./core/result.js";
export type { ToolEffect, ToolHints, ToolResult, ToolStatus } from "./core/result.js";
export {
  DEFAULT_TEXT_LIMIT,
  NOTICE_KEY,
  redactDigitRuns,
  redactEmails,
  redactPattern,
  sanitizeLeaves,
  sanitizeText,
  withDataNotice,
} from "./core/sanitize.js";
export type { Redactor, SanitizeOptions } from "./core/sanitize.js";
export { defineScopes, hasScope, mixesReadAndWrite, parseScopes, scopesOfNature } from "./core/scopes.js";
export type { ScopeCatalog, ScopeDefinition, ScopeNature } from "./core/scopes.js";
export { resolveTarget } from "./core/tenant.js";
export type { AccessMode, Target, TargetDecision } from "./core/tenant.js";
export {
  DEFAULT_TTL_DAYS,
  MAX_TTL_DAYS,
  candidateHashes,
  classifyToken,
  generateToken,
  hashToken,
  tokenPrefix,
  tokenUsability,
} from "./core/tokens.js";
export type { HashVersion, IssuedToken, TokenClass, TokenHash } from "./core/tokens.js";

export { authenticate, bearerToken } from "./guard/authenticate.js";
export { createGuard } from "./guard/guard.js";
export type { AgentDefinition, Guard, GuardConfig, GuardEvent, OAuthConfig } from "./guard/guard.js";
export { issueCredential, listCredentials, revokeCredential } from "./guard/issue.js";
export type { CredentialSummary, IssueFailure, IssueRequest, IssueResult } from "./guard/issue.js";
export { runTools } from "./guard/runs.js";
export { assertTools, defineTool, executeTool, isVisible } from "./guard/tool.js";
export type { AnyTool, RequestContext, ToolCall, ToolDefinition } from "./guard/tool.js";

export { createMcpHandler, forwardedIp } from "./http/mcp.js";
export type { McpHandlerOptions } from "./http/mcp.js";
export { createOAuthHandler } from "./http/oauth.js";
export type { OAuthHandlerOptions } from "./http/oauth.js";

export { challengeFor, verifyPkce } from "./oauth/pkce.js";
export { isAllowedRedirect, redirectHost } from "./oauth/redirects.js";
export type { RedirectFamily, RedirectPolicy } from "./oauth/redirects.js";
export {
  approveAuthorization,
  authorizationServerMetadata,
  denyAuthorization,
  exchangeToken,
  listConnections,
  protectedResourceMetadata,
  registerClient,
  revokeConnection,
  validateAuthorizeRequest,
} from "./oauth/server.js";
export type { Approval, ApprovalResult, AuthorizeCheck, AuthorizeRequest, ConnectionSummary, OAuthPaths, TokenResult } from "./oauth/server.js";

export { MemoryAuditStore, MemoryCredentialStore, MemoryOAuthStore, MemoryRunStore } from "./store/memory.js";
export type {
  AgentRun,
  AuthorizationCode,
  CredentialRecord,
  CredentialStore,
  OAuthClient,
  OAuthGrant,
  OAuthStore,
  RevokeResult,
  RunStatus,
  RunStore,
} from "./store/types.js";
