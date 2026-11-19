// One path for every tool call.
//
// A tool author writes the part that reads or changes data. Everything that must not be forgotten
// happens around it, in a fixed order, in one place:
//
//   budget -> arguments -> visibility -> scope -> cost -> tenant -> audit (open) -> handler
//   -> sanitize -> size -> audit (close)
//
// A handler never sees a request before those steps have run. What the wrapper cannot do is check
// that a tool told the truth about itself: a tool declared as a read that writes anyway, or one
// that ignores the tenant it was handed, is not caught here. Declarations are reviewed by people.

import { z } from "zod";

import type { Actor, ActorKind } from "../core/actor.js";
import { auditParams, pickLoggable } from "../core/audit.js";
import type { NewAuditEntry } from "../core/audit.js";
import { ToolError, TOOL_HINTS, TOOL_STATUSES, enforceResultSize, errorResult, okResult, statusOf } from "../core/result.js";
import type { ToolEffect, ToolResult, ToolStatus } from "../core/result.js";
import { sanitizeLeaves, sanitizeText, withDataNotice } from "../core/sanitize.js";
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
  /** Scope the credential must hold. Null only for a tool that touches no tenant data. */
  scope: string | null;
  /** What the tool does. Decides the hints, the kind of scope it needs and who may see it. */
  effect: ToolEffect;
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

/**
 * The guard's own tools that change nothing but the guard's records (runs). They are the only
 * tools allowed to write without a write scope, and a tool cannot put itself on this list.
 */
const BOOKKEEPING = new WeakSet<object>();

/** @internal */
export function markBookkeeping<T extends AnyTool>(tool: T): T {
  BOOKKEEPING.add(tool);
  return tool;
}

/** How the tool touches the tenant. Follows from its effect; a tool cannot declare it separately. */
export function accessOf(tool: AnyTool): AccessMode {
  if (BOOKKEEPING.has(tool)) return "read";
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
      // Without a scope there is nothing to say who may change things, so nothing may be changed.
      if (accessOf(tool) !== "read") throw new Error(`${tool.name}: a tool without a scope must be a read`);
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

/**
 * Starts the work unless time is already up, and stops waiting for it when time runs out.
 *
 * The work is STARTED here, after the check, never before: a handler that begins once the caller
 * has been told "timed out" is a write nobody is waiting for. Work that is abandoned mid-flight
 * keeps its rejection handler, so a late failure is ignored instead of crashing the process.
 */
function abortRace<T>(start: () => Promise<T>, signal: AbortSignal, onAbort: () => ToolError): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    if (signal.aborted) return reject(onAbort());
    const stop = () => reject(onAbort());
    signal.addEventListener("abort", stop, { once: true });
    let work: Promise<T>;
    try {
      work = start();
    } catch (err) {
      signal.removeEventListener("abort", stop);
      return reject(err);
    }
    work.then(resolve, reject).finally(() => signal.removeEventListener("abort", stop));
  });
}

function auditEntry(guard: Guard, context: RequestContext, tool: string, tenantId: string | null, params: Record<string, unknown>): NewAuditEntry {
  const { actor } = context;
  return {
    at: guard.now(),
    credentialId: actor.credentialId,
    userId: actor.userId,
    actorKind: actor.kind,
    agentName: actor.agentName,
    tenantId,
    tool,
    params: auditParams(params),
    traceId: context.traceId,
    runId: context.runId,
  };
}

/**
 * Leaves a durable trace of a call that was refused before it ran. The refusal stands whether or
 * not it could be recorded, but a failure to record it is reported: a lost refusal is a blind spot.
 */
export async function recordRefusal(
  guard: Guard,
  context: RequestContext,
  refusal: { tool: string; tenantId: string | null; status: number; params?: Record<string, unknown> },
): Promise<void> {
  const tool = sanitizeText(refusal.tool, { maxLength: 64 });
  const tenantId = refusal.tenantId === null ? null : sanitizeText(refusal.tenantId, { maxLength: 200 });
  try {
    await guard.audit.denied({ ...auditEntry(guard, context, tool, tenantId, refusal.params ?? {}), status: refusal.status });
  } catch (err) {
    guard.emit({ type: "audit_denied_failed", traceId: context.traceId, detail: { tool, status: refusal.status, error: String(err) } });
  }
}

/** Runs one tool call through every check. Never throws: a failure is a result. */
export async function executeTool(guard: Guard, context: RequestContext, tool: AnyTool, rawArgs: unknown): Promise<ToolResult> {
  const { actor, traceId, signal } = context;
  const startedAt = guard.now().getTime();
  const access = accessOf(tool);
  let auditId: string | null = null;
  let requestedTenant: string | null = null;
  let loggable: Record<string, unknown> = {};
  let result: ToolResult;

  /** Refuses the call before it ran, on the record. */
  const refuse = async (status: ToolStatus, message: string): Promise<ToolError> => {
    await recordRefusal(guard, context, { tool: tool.name, tenantId: requestedTenant, status, params: loggable });
    return new ToolError(status, message);
  };

  try {
    // One request can batch several calls, and the budget belongs to the request: once it is
    // spent, the remaining calls do not start.
    if (signal.aborted) throw await refuse(504, "The request ran out of time before this call started.");

    const parsed = z.object(inputShape(tool)).safeParse(rawArgs ?? {});
    if (!parsed.success) throw await refuse(400, `Invalid arguments: ${parsed.error.issues[0]?.message ?? "check the input"}`);
    const args = parsed.data as Record<string, unknown>;
    requestedTenant = typeof args.tenantId === "string" ? args.tenantId : null;
    loggable = pickLoggable(args, tool.audit ?? []);

    // Checked again here although hidden tools are not listed: the list is a courtesy, this is
    // the control.
    if (!isVisible(guard, actor, tool)) {
      throw await refuse(
        403,
        tool.scope && !hasScope(guard.scopes, actor.scopes, tool.scope)
          ? `This credential lacks the scope ${tool.scope}.`
          : "This credential cannot use this tool.",
      );
    }

    const cost = typeof tool.cost === "function" ? tool.cost(args) : (tool.cost ?? 1);
    // A cost that is not a positive number would switch the limit off, or pay the caller back.
    if (!Number.isFinite(cost) || cost <= 0) throw new Error(`tool ${tool.name} computed an invalid cost`);
    const charge = await guard.limiter.consume([
      { key: `cost:credential:${actor.credentialId}`, rule: guard.limits.costPerCredential, cost },
      // Keyed by kind as well, so a looping agent cannot spend its delegator's own budget.
      { key: `cost:user:${actor.kind}:${actor.userId}`, rule: guard.limits.costPerUser, cost },
    ]);
    if (!charge.allowed) throw await refuse(429, `Usage limit reached. Try again in ${charge.retryAfterSeconds} seconds.`);

    let target: Target | null = null;
    if (tool.tenant !== false) {
      const decision = await resolveTarget(actor, requestedTenant, access, guard.directory);
      if (!decision.ok) throw await refuse(decision.status, decision.message);
      target = decision.target;
    }

    // The row exists BEFORE the data is touched. If it cannot be written, nothing is read: there
    // is no access without a record of it.
    try {
      auditId = await guard.audit.open(auditEntry(guard, context, tool.name, target?.tenantId ?? null, loggable));
    } catch {
      throw new ToolError(503, "The audit log is unavailable, so the call was not run. Try again shortly.");
    }

    const toolArgs = Object.fromEntries(Object.entries(args).filter(([key]) => key !== "tenantId"));
    const payload = await abortRace(
      () => tool.handler({ args: toolArgs, actor, target, traceId, runId: context.runId, signal }),
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
    detail: {
      tool: tool.name,
      credentialId: actor.credentialId,
      userId: actor.userId,
      tenantId: requestedTenant === null ? null : sanitizeText(requestedTenant, { maxLength: 200 }),
      status,
      durationMs,
    },
  });
  return result;
}

export function toolHints(tool: AnyTool) {
  return { title: tool.title, ...TOOL_HINTS[tool.effect] };
}
