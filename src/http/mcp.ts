// The MCP endpoint: a function from a web `Request` to a `Response`.
//
// Stateless. Each request authenticates, builds a server holding only the tools this actor may
// use, answers, and is gone. There is no session to steal and nothing to keep in sync between
// instances.

import { randomUUID } from "node:crypto";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";

import type { Actor } from "../core/actor.js";
import { authenticate } from "../guard/authenticate.js";
import type { Guard } from "../guard/guard.js";
import { openRunId, runTools } from "../guard/runs.js";
import { assertTools, executeTool, inputShape, isVisible, toolHints } from "../guard/tool.js";
import type { AnyTool, RequestContext } from "../guard/tool.js";
import { wwwAuthenticate } from "../oauth/server.js";

export interface McpHandlerOptions {
  name: string;
  version: string;
  tools: readonly AnyTool[];
  /** Server instructions for this actor. How the model should behave goes here, not in tool descriptions. */
  instructions?: (actor: Actor) => string;
  /**
   * The caller's IP, for the limit applied before authentication. Only trust a forwarding header
   * when a proxy you control overwrites it. Without this option every caller shares one bucket.
   */
  clientIp?: (request: Request) => string | null;
  /**
   * Origins allowed to call from a browser. A request carrying any other `Origin` is refused.
   * Requests without the header (every non-browser client) are not affected.
   */
  allowedOrigins?: readonly string[];
}

export const UNAUTHORIZED_BODY = JSON.stringify({ error: "unauthorized" });

function json(status: number, body: string, headers: Record<string, string> = {}): Response {
  return new Response(body, { status, headers: { "content-type": "application/json", "cache-control": "no-store", ...headers } });
}

export function createMcpHandler(guard: Guard, options: McpHandlerOptions): (request: Request) => Promise<Response> {
  const tools = [...options.tools, ...runTools(guard)];
  assertTools(guard, tools);

  return async (request) => {
    if (request.method !== "POST") return json(405, JSON.stringify({ error: "method not allowed" }), { allow: "POST" });

    const origin = request.headers.get("origin");
    if (origin && !(options.allowedOrigins ?? []).includes(origin)) {
      return json(403, JSON.stringify({ error: "origin not allowed" }));
    }

    // Before any lookup: a flood of made-up tokens is stopped by a counter, not by the database.
    const ip = options.clientIp?.(request) ?? "unknown";
    const anonymous = await guard.limiter.consume([{ key: `ip:${ip}`, rule: guard.limits.anonymousPerIp }]);
    if (!anonymous.allowed) {
      return json(429, JSON.stringify({ error: "too many requests" }), { "retry-after": String(anonymous.retryAfterSeconds) });
    }

    const actor = await authenticate(guard, request.headers.get("authorization"));
    if (!actor) {
      const challenge = wwwAuthenticate(guard);
      return json(401, UNAUTHORIZED_BODY, challenge ? { "www-authenticate": challenge } : {});
    }

    const perCredential = await guard.limiter.consume([{ key: `credential:${actor.credentialId}`, rule: guard.limits.perCredential }]);
    if (!perCredential.allowed) {
      return json(429, JSON.stringify({ error: "too many requests" }), { "retry-after": String(perCredential.retryAfterSeconds) });
    }

    // Generated here. A client-supplied id would be attacker-chosen text in every log line.
    const traceId = randomUUID();
    const budget = new AbortController();
    const timer = setTimeout(() => budget.abort(), guard.toolBudgetMs);
    const context: RequestContext = {
      actor,
      traceId,
      signal: budget.signal,
      runId: actor.kind === "agent" ? await openRunId(guard, actor.credentialId) : null,
    };

    try {
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
      const response = await transport.handleRequest(request);
      const headers = new Headers(response.headers);
      headers.set("x-trace-id", traceId);
      headers.set("cache-control", "no-store");
      return new Response(response.body, { status: response.status, headers });
    } catch (err) {
      guard.emit({ type: "internal_error", traceId, message: "mcp request failed", detail: { error: err instanceof Error ? err.message : String(err) } });
      return json(500, JSON.stringify({ error: "internal error", reference: traceId }));
    } finally {
      clearTimeout(timer);
    }
  };
}

/**
 * First hop of `X-Forwarded-For`. Correct ONLY behind a proxy that overwrites the header; anywhere
 * else the caller chooses its own rate-limit bucket.
 */
export function forwardedIp(request: Request): string | null {
  const first = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  return first && first.length <= 64 ? first : null;
}
