// The OAuth endpoints that need no signed-in person: discovery, registration and the token
// endpoint. The authorization page is not here, because it belongs behind the host's own session.

import type { Guard } from "../guard/guard.js";
import {
  DEFAULT_OAUTH_PATHS,
  authorizationServerMetadata,
  clientRegistrationResponse,
  exchangeToken,
  protectedResourceMetadata,
  registerClient,
} from "../oauth/server.js";
import type { OAuthPaths } from "../oauth/server.js";

export interface OAuthHandlerOptions {
  paths?: OAuthPaths;
  /** See `McpHandlerOptions.clientIp`. */
  clientIp?: (request: Request) => string | null;
}

const NO_STORE = { "cache-control": "no-store", pragma: "no-cache" };

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...NO_STORE, ...headers } });
}

const notFound = () => new Response(null, { status: 404, headers: NO_STORE });

async function readParams(request: Request): Promise<Record<string, string> | null> {
  try {
    const type = request.headers.get("content-type") ?? "";
    if (type.includes("application/json")) {
      const body: unknown = await request.json();
      if (!body || typeof body !== "object" || Array.isArray(body)) return null;
      const params: Record<string, string> = {};
      for (const [key, value] of Object.entries(body)) if (typeof value === "string") params[key] = value;
      return params;
    }
    return Object.fromEntries(new URLSearchParams(await request.text()));
  } catch {
    return null;
  }
}

/**
 * Handles the request if it is for one of the OAuth endpoints, and returns null otherwise. With
 * OAuth switched off every one of them answers 404, before reading anything.
 */
export function createOAuthHandler(guard: Guard, options: OAuthHandlerOptions = {}): (request: Request) => Promise<Response | null> {
  const paths = options.paths ?? DEFAULT_OAUTH_PATHS;

  return async (request) => {
    const { pathname } = new URL(request.url);
    const isResourceMetadata =
      pathname === "/.well-known/oauth-protected-resource" || pathname.startsWith("/.well-known/oauth-protected-resource/");
    const isServerMetadata = pathname === "/.well-known/oauth-authorization-server";
    const isRegister = pathname === paths.register;
    const isToken = pathname === paths.token;
    if (!isResourceMetadata && !isServerMetadata && !isRegister && !isToken) return null;
    if (!guard.oauth || !guard.oauthEnabled()) return notFound();

    if (isResourceMetadata || isServerMetadata) {
      if (request.method !== "GET") return json(405, { error: "method not allowed" }, { allow: "GET" });
      const metadata = isResourceMetadata ? protectedResourceMetadata(guard) : authorizationServerMetadata(guard, paths);
      return new Response(JSON.stringify(metadata), {
        status: 200,
        headers: { "content-type": "application/json", "cache-control": "public, max-age=300" },
      });
    }

    if (request.method !== "POST") return json(405, { error: "method not allowed" }, { allow: "POST" });
    const ip = options.clientIp?.(request) ?? "unknown";

    // The limit is consumed before the body is read: a rejected request costs nothing to parse.
    const rule = isRegister ? guard.limits.registrationPerIp : guard.limits.tokenEndpointPerIp;
    const limit = await guard.limiter.consume([{ key: `${isRegister ? "register" : "token"}:${ip}`, rule }]);
    if (!limit.allowed) return json(429, { error: "too_many_requests" }, { "retry-after": String(limit.retryAfterSeconds) });

    if (isRegister) {
      let body: unknown;
      try {
        body = await request.json();
      } catch {
        return json(400, { error: "invalid_client_metadata", error_description: "The body must be JSON." });
      }
      const result = await registerClient(guard, body);
      if (!result.ok) return json(result.status, { error: result.error, error_description: result.description });
      return json(201, clientRegistrationResponse(result.client));
    }

    const params = await readParams(request);
    if (!params) return json(400, { error: "invalid_request", error_description: "The body could not be read." });
    const result = await exchangeToken(guard, params);
    if (!result.ok) return json(result.status, { error: result.error, error_description: result.description });
    return json(200, result.body);
  };
}
