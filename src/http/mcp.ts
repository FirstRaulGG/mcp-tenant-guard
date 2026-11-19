// The MCP endpoint: a function from a web `Request` to a `Response`.
//
// Stateless. Each request authenticates, builds a server holding only the tools this actor may
// use, answers, and is gone. There is no session to steal and nothing to keep in sync between
// instances.

import { randomUUID } from "node:crypto";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { z } from "zod";

import type { Actor } from "../core/actor.js";
import { sanitizeText } from "../core/sanitize.js";
import { authenticate } from "../guard/authenticate.js";
import type { Guard } from "../guard/guard.js";
import { openRunId, runTools } from "../guard/runs.js";
import { assertTools, executeTool, inputShape, isVisible, recordRefusal, toolHints } from "../guard/tool.js";
import type { AnyTool, RequestContext } from "../guard/tool.js";
import { wwwAuthenticate } from "../oauth/server.js";

export interface McpHandlerOptions {
  name: string;
  version: string;
  tools: readonly AnyTool[];
  /** Server instructions for this actor. How the model should behave goes here, not in tool descriptions. */
  instructions?: (actor: Actor) => string;
  /**
   * The caller's IP, for the limit applied before authentication. See `forwardedIp`. Without this
   * option there is NO limit before authentication: one bucket shared by every caller would let
   * anyone lock everyone out, so none is kept.
   */
  clientIp?: (request: Request) => string | null;
  /**
   * Origins allowed to call from a browser. A request carrying any other `Origin` is refused.
   * Requests without the header (every non-browser client) are not affected.
   */
  allowedOrigins?: readonly string[];
  /** Largest request body accepted, in bytes. Default 1 MB. */
  maxBodyBytes?: number;
}

export const UNAUTHORIZED_BODY = JSON.stringify({ error: "unauthorized" });
const DEFAULT_MAX_BODY_BYTES = 1_000_000;

function json(status: number, body: string, headers: Record<string, string> = {}): Response {
  return new Response(body, { status, headers: { "content-type": "application/json", "cache-control": "no-store", ...headers } });
}

/** The tool calls in a JSON-RPC body, single or batched. Anything unreadable yields none. */
function toolCallsIn(body: string): ObservedCall[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return [];
  }
  const calls: ObservedCall[] = [];
  for (const message of Array.isArray(parsed) ? parsed : [parsed]) {
    if (!message || typeof message !== "object") continue;
    const { method, params } = message as { method?: unknown; params?: unknown };
    if (method !== "tools/call" || !params || typeof params !== "object") continue;
    const { name, arguments: args } = params as { name?: unknown; arguments?: unknown };
    if (typeof name !== "string") continue;
    const tenantId = args && typeof args === "object" ? (args as { tenantId?: unknown }).tenantId : null;
    calls.push({ name, args, tenantId: typeof tenantId === "string" ? tenantId : null });
  }
  return calls;
}

interface ObservedCall {
  name: string;
  args: unknown;
  tenantId: string | null;
}

export function createMcpHandler(guard: Guard, options: McpHandlerOptions): (request: Request) => Promise<Response> {
  const tools = [...options.tools, ...runTools(guard)];
  assertTools(guard, tools);
  const byName = new Map(tools.map((tool) => [tool.name, tool]));
  const maxBodyBytes = options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  if (!options.clientIp) {
    guard.emit({ type: "config_warning", message: "no clientIp option: requests are not rate limited before authentication" });
  }

  return async (request) => {
    // Generated here. A client-supplied id would be attacker-chosen text in every log line.
    const traceId = randomUUID();
    let timer: ReturnType<typeof setTimeout> | undefined;

    try {
      if (request.method !== "POST") return json(405, JSON.stringify({ error: "method not allowed" }), { allow: "POST" });

      const origin = request.headers.get("origin");
      if (origin && !(options.allowedOrigins ?? []).includes(origin)) {
        return json(403, JSON.stringify({ error: "origin not allowed" }));
      }

      // Before any lookup: a flood of made-up tokens is stopped by a counter, not by the database.
      const ip = options.clientIp?.(request) ?? null;
      if (ip) {
        const anonymous = await guard.limiter.consume([{ key: `ip:${ip}`, rule: guard.limits.anonymousPerIp }]);
        if (!anonymous.allowed) {
          guard.emit({ type: "rate_limited", traceId, detail: { stage: "before_authentication" } });
          return json(429, JSON.stringify({ error: "too many requests" }), { "retry-after": String(anonymous.retryAfterSeconds) });
        }
      }

      const actor = await authenticate(guard, request.headers.get("authorization"));
      if (!actor) {
        // Reported, so that someone trying tokens is visible to whoever runs the server. The
        // token is not in the event.
        guard.emit({ type: "unauthorized", traceId });
        const challenge = wwwAuthenticate(guard);
        return json(401, UNAUTHORIZED_BODY, challenge ? { "www-authenticate": challenge } : {});
      }

      const perCredential = await guard.limiter.consume([{ key: `credential:${actor.credentialId}`, rule: guard.limits.perCredential }]);
      if (!perCredential.allowed) {
        guard.emit({ type: "rate_limited", traceId, detail: { stage: "per_credential", credentialId: actor.credentialId } });
        return json(429, JSON.stringify({ error: "too many requests" }), { "retry-after": String(perCredential.retryAfterSeconds) });
      }

      const declared = Number(request.headers.get("content-length") ?? 0);
      if (declared > maxBodyBytes) return json(413, JSON.stringify({ error: "request too large" }));
      const body = await request.text();
      if (Buffer.byteLength(body, "utf8") > maxBodyBytes) return json(413, JSON.stringify({ error: "request too large" }));

      const budget = new AbortController();
      timer = setTimeout(() => budget.abort(), guard.toolBudgetMs);
      const context: RequestContext = {
        actor,
        traceId,
        signal: budget.signal,
        runId: actor.kind === "agent" ? await openRunId(guard, actor.credentialId) : null,
      };

      // A call to a tool this actor is not offered never reaches the tool pipeline: the protocol
      // layer answers "no such tool". It is exactly the call worth knowing about (a model doing
      // what a note told it to), so it is put on the record here.
      for (const call of toolCallsIn(body)) {
        const tool = byName.get(call.name);
        if (tool && isVisible(guard, actor, tool)) {
          // Same for arguments the protocol layer will reject on its own.
          if (!z.object(inputShape(tool)).safeParse(call.args ?? {}).success) {
            await recordRefusal(guard, context, { tool: tool.name, tenantId: call.tenantId, status: 400 });
          }
          continue;
        }
        if (tool) {
          await recordRefusal(guard, context, { tool: tool.name, tenantId: call.tenantId, status: 403 });
        } else {
          guard.emit({ type: "refused", traceId, detail: { reason: "unknown_tool", tool: sanitizeText(call.name, { maxLength: 64 }), credentialId: actor.credentialId } });
        }
      }

      const server = new McpServer(
        { name: options.name, version: options.version },
        { instructions: options.instructions?.(actor) },
      );
      for (const tool of tools) {
        if (!isVisible(guard, actor, tool)) continue;
        server.registerTool(
          tool.name,
          { title: tool.title, description: tool.description, inputSchema: inputShape(tool), annotations: toolHints(tool) },
          (args: unknown) => executeTool(guard, context, tool, args),
        );
      }

      const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      await server.connect(transport);
      const response = await transport.handleRequest(new Request(request.url, { method: "POST", headers: request.headers, body }));
      const headers = new Headers(response.headers);
      headers.set("x-trace-id", traceId);
      headers.set("cache-control", "no-store");
      return new Response(response.body, { status: response.status, headers });
    } catch (err) {
      // Includes a failure of the directory or the store while authenticating. The caller gets a
      // reference; the message, which may hold a connection string, goes to the operator.
      guard.emit({ type: "internal_error", traceId, message: "mcp request failed", detail: { error: err instanceof Error ? err.message : String(err) } });
      return json(500, JSON.stringify({ error: "internal error", reference: traceId }));
    } finally {
      clearTimeout(timer);
    }
  };
}

/**
 * Builds a `clientIp` function from `X-Forwarded-For`.
 *
 * `trustedProxies` is how many proxies YOU run in front of this server, each appending the address
 * it received the request from. The client's address is then that many entries from the right;
 * everything to the left of it was written by the client and is ignored. With the wrong number the
 * caller chooses its own rate-limit bucket, so count them.
 */
export function forwardedIp(trustedProxies: number): (request: Request) => string | null {
  if (!Number.isInteger(trustedProxies) || trustedProxies < 1) throw new Error("trustedProxies must be an integer of at least 1");
  return (request) => {
    const hops = (request.headers.get("x-forwarded-for") ?? "").split(",").map((hop) => hop.trim()).filter(Boolean);
    const hop = hops[hops.length - trustedProxies];
    return hop && /^[0-9a-fA-F:.]{2,45}$/.test(hop) ? hop : null;
  };
}
