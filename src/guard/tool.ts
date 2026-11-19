// One path for every tool call.
//
// A tool author writes the part that reads or changes data. Everything that must not be forgotten
// happens around it, in a fixed order, in one place:
//
//   budget -> visibility -> scope -> cost -> tenant -> audit (open) -> handler -> sanitize -> size
//   -> audit (close)
//
// A tool cannot skip a step, because it never sees the request before the steps have run.

import { z } from "zod";

import type { Actor, ActorKind } from "../core/actor.js";
import { auditParams, pickLoggable } from "../core/audit.js";
import type { NewAuditEntry } from "../core/audit.js";
import { ToolError, TOOL_HINTS, TOOL_STATUSES, enforceResultSize, errorResult, okResult, statusOf } from "../core/result.js";
import type { ToolEffect, ToolResult, ToolStatus } from "../core/result.js";
import { sanitizeLeaves, withDataNotice } from "../core/sanitize.js";
import { hasScope } from "../core/scopes.js";
import { resolveTarget } from "../core/tenant.js";
import type { AccessMode, Target } from "../core/tenant.js";
import type { Guard } from "./guard.js";

export interface ToolCall<Args> {
  args: Args;
  actor: Actor;
  /** The tenant this call was resolved to. Null only for tools declared with `tenant: false`. */
  target: Target | null;
  traceId: string;
  runId: string | null;
  signal: AbortSignal;
}

export interface ToolDefinition<Shape extends z.ZodRawShape = z.ZodRawShape> {
  name: string;
  title: string;
  /** States what the tool returns. Facts, not orders: how to behave belongs in server instructions. */
  description: string;
  /** Arguments, without `tenantId`: the guard adds and resolves it. */
  input: Shape;
  /** Scope the credential must hold. Null for a tool that touches no tenant data. */
  scope: string | null;
  effect: ToolEffect;
  /** How the tenant is accessed. Defaults from `effect`. */
  access?: AccessMode;
  /** Set to false for a tool that is not about one tenant, such as listing them. */
  tenant?: boolean;
  /** Restricts the tool to some kinds of actor. Default: all. */
  actors?: readonly ActorKind[];
  /** Units charged against the cost limits. Default 1. */
  cost?: number | ((args: z.infer<z.ZodObject<Shape>>) => number);
  /** Paths in the result holding text written by outsiders, for the notice. */
  untrusted?: readonly string[];
  /** Argument names that may be written to the audit log. Free text should not be listed. */
  audit?: readonly string[];
  handler(call: ToolCall<z.infer<z.ZodObject<Shape>>>): Promise<Record<string, unknown>>;
}

/** Identity helper that keeps the argument types of `handler` tied to `input`. */
export function defineTool<Shape extends z.ZodRawShape>(tool: ToolDefinition<Shape>): ToolDefinition<Shape> {
  return tool;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type AnyTool = ToolDefinition<any>;

export function accessOf(tool: AnyTool): AccessMode {
  if (tool.access) return tool.access;
  if (tool.effect === "write" || tool.effect === "overwrite") return "write";
  return tool.effect === "propose" ? "propose" : "read";
}

/** Fails at start-up on a tool whose declared scope does not match what it does. */
export function assertTools(guard: Guard, tools: readonly AnyTool[]): void {
  const names = new Set<string>();
  for (const tool of tools) {
    if (!/^[a-z][a-z0-9_]{1,63}$/.test(tool.name)) throw new Error(`invalid tool name: ${tool.name}`);
    if (names.has(tool.name)) throw new Error(`tool declared twice: ${tool.name}`);
    names.add(tool.name);
    if ("tenantId" in tool.input) throw new Error(`${tool.name}: tenantId is added by the guard, do not declare it`);
    if (tool.scope === null) {
      if (tool.tenant !== false) throw new Error(`${tool.name}: a tool that reads a tenant needs a scope`);
      continue;
    }
    const nature = guard.scopes.natureOf(tool.scope);
    if (!nature) throw new Error(`${tool.name}: unknown scope ${tool.scope}`);
    // A write behind a read scope would make every read token a write token.
    if (nature !== accessOf(tool)) {
      throw new Error(`${tool.name}: a tool that does "${accessOf(tool)}" cannot be gated by the ${nature} scope ${tool.scope}`);
    }
  }
}

/**
 * Whether the actor may use the tool at all. A tool that fails this is left out of the list the
 * client sees, rather than offered and then refused: a control that cannot act should not appear.
 */
export function isVisible(guard: Guard, actor: Actor, tool: AnyTool): boolean {
  if (tool.actors && !tool.actors.includes(actor.kind)) return false;
  if (tool.scope !== null && !hasScope(guard.scopes, actor.scopes, tool.scope)) return false;
  const access = accessOf(tool);
  if (actor.kind === "agent" && access === "write") return false;
  if (actor.kind === "owner" && actor.role === "viewer" && access !== "read") return false;
  return true;
}

export const TENANT_ARGUMENT = z
  .string()
  .max(200)
  .optional()
  .describe("Id of the tenant, as returned by the tool that lists tenants. Required for an advisor; a credential bound to one tenant may omit it.");

export function inputShape(tool: AnyTool): z.ZodRawShape {
  return tool.tenant === false ? tool.input : { ...tool.input, tenantId: TENANT_ARGUMENT };
}

export interface RequestContext {
  actor: Actor;
  traceId: string;
  /** Aborts when the request's tool budget runs out. Shared by every call in the request. */
  signal: AbortSignal;
  runId: string | null;
}

function isToolStatus(status: number): status is ToolStatus {
  return (TOOL_STATUSES as readonly number[]).includes(status);
}

function abortRace<T>(work: Promise<T>, signal: AbortSignal, onAbort: () => ToolError): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const stop = () => reject(onAbort());
    if (signal.aborted) return stop();
    signal.addEventListener("abort", stop, { once: true });
    work.then(resolve, reject).finally(() => signal.removeEventListener("abort", stop));
  });
}

/** Runs one tool call through every check. Never throws: a failure is a result. */
export async function executeTool(guard: Guard, context: RequestContext, tool: AnyTool, rawArgs: unknown): Promise<ToolResult> {
  const { actor, traceId, signal } = context;
  const startedAt = guard.now().getTime();
  const access = accessOf(tool);
  let auditId: string | null = null;
  let requestedTenant: string | null = null;
  let result: ToolResult;

  const entry = (tenantId: string | null, params: Record<string, unknown>): NewAuditEntry => ({
    at: guard.now(),
    credentialId: actor.credentialId,
    userId: actor.userId,
    actorKind: actor.kind,
    agentName: actor.agentName,
    tenantId,
    tool: tool.name,
    params: auditParams(params),
    traceId,
    runId: context.runId,
  });

  /** Refuses the call and leaves a durable trace of the attempt. */
  const deny = async (status: 403 | 404, message: string): Promise<never> => {
    try {
      await guard.audit.denied({ ...entry(requestedTenant, {}), status });
    } catch {
      // The refusal stands whether or not it could be recorded.
    }
    throw new ToolError(status, message);
  };

  try {
    // One request can batch several calls, and the budget belongs to the request: once it is
    // spent, the remaining calls do not start.
    if (signal.aborted) throw new ToolError(504, "The request ran out of time before this call started.");

    const parsed = z.object(inputShape(tool)).safeParse(rawArgs ?? {});
    if (!parsed.success) throw new ToolError(400, `Invalid arguments: ${parsed.error.issues[0]?.message ?? "check the input"}`);
    const args = parsed.data as Record<string, unknown>;
    requestedTenant = typeof args.tenantId === "string" ? args.tenantId.slice(0, 200) : null;

    // Checked again here although hidden tools are not listed: the list is a courtesy, this is
    // the control.
    if (!isVisible(guard, actor, tool)) {
      await deny(403, tool.scope && !hasScope(guard.scopes, actor.scopes, tool.scope)
        ? `This credential lacks the scope ${tool.scope}.`
        : "This credential cannot use this tool.");
    }

    const cost = typeof tool.cost === "function" ? tool.cost(args) : (tool.cost ?? 1);
    const charge = await guard.limiter.consume([
      { key: `cost:credential:${actor.credentialId}`, rule: guard.limits.costPerCredential, cost },
      // Keyed by kind as well, so a looping agent cannot spend its delegator's own budget.
      { key: `cost:user:${actor.kind}:${actor.userId}`, rule: guard.limits.costPerUser, cost },
    ]);
    if (!charge.allowed) throw new ToolError(429, `Usage limit reached. Try again in ${charge.retryAfterSeconds} seconds.`);

    let target: Target | null = null;
    if (tool.tenant !== false) {
      const decision = await resolveTarget(actor, requestedTenant, access, guard.directory);
      if (!decision.ok) await deny(decision.status, decision.message);
      else target = decision.target;
    }

    // The row exists BEFORE the data is touched. If it cannot be written, nothing is read: there
    // is no access without a record of it.
    try {
      auditId = await guard.audit.open(entry(target?.tenantId ?? null, pickLoggable(args, tool.audit ?? [])));
    } catch {
      throw new ToolError(503, "The audit log is unavailable, so the call was not run. Try again shortly.");
    }

    const toolArgs = Object.fromEntries(Object.entries(args).filter(([key]) => key !== "tenantId"));
    const payload = await abortRace(
      tool.handler({ args: toolArgs, actor, target, traceId, runId: context.runId, signal }),
      signal,
      () =>
        new ToolError(
          504,
          access === "read"
            ? "The call took too long. Ask for a shorter period or fewer rows."
            : "The call took too long and may still complete. Check the current state before trying again.",
        ),
    );

    const cleaned = sanitizeLeaves(payload, guard.sanitize) as Record<string, unknown>;
    result = enforceResultSize(okResult(withDataNotice(cleaned, tool.untrusted ?? [])), guard.maxResultBytes);
  } catch (err) {
    if (err instanceof ToolError && isToolStatus(err.status)) {
      result = errorResult(err.status, err.message);
    } else {
      // The model gets a reference, the operator gets the detail.
      guard.emit({ type: "internal_error", traceId, message: tool.name, detail: { error: err instanceof Error ? err.message : String(err) } });
      result = errorResult(500, `Internal error while running the tool. Reference: ${traceId}`);
    }
  }

  const status = statusOf(result);
  const durationMs = guard.now().getTime() - startedAt;
  if (auditId) {
    try {
      await guard.audit.close(auditId, { outcome: status === 200 ? "ok" : "error", status, durationMs });
    } catch (err) {
      // The call already happened and its opening row exists. Losing the closing update leaves that
      // row marked open, which is itself a signal.
      guard.emit({ type: "audit_close_failed", traceId, detail: { error: String(err) } });
    }
  }
  guard.emit({
    type: "tool",
    traceId,
    detail: { tool: tool.name, credentialId: actor.credentialId, userId: actor.userId, tenantId: requestedTenant, status, durationMs },
  });
  return result;
}

export function toolHints(tool: AnyTool) {
  return { title: tool.title, ...TOOL_HINTS[tool.effect] };
}
