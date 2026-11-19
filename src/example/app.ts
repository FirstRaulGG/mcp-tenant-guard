// Wires the example together: one guard, one MCP endpoint, the OAuth endpoints.

import { redactEmails } from "../core/sanitize.js";
import { createGuard } from "../guard/guard.js";
import type { Guard, GuardConfig, GuardEvent } from "../guard/guard.js";
import { createMcpHandler } from "../http/mcp.js";
import { createOAuthHandler } from "../http/oauth.js";
import { MemoryAuditStore, MemoryCredentialStore, MemoryOAuthStore, MemoryRunStore } from "../store/memory.js";
import { HARBOR_AGENTS, HARBOR_SCOPES, harborInstructions, harborTools } from "./tools.js";
import { createWorld } from "./world.js";
import type { World } from "./world.js";

export interface HarborOptions {
  /** Where the example is reachable. Default `http://localhost:8787`. */
  origin?: string;
  now?: () => Date;
  /** How to find the caller's IP. Absent, requests are not limited before authentication. */
  clientIp?: (request: Request) => string | null;
  overrides?: Partial<GuardConfig>;
}

export interface Harbor {
  world: World;
  guard: Guard;
  credentials: MemoryCredentialStore;
  oauthStore: MemoryOAuthStore;
  audit: MemoryAuditStore;
  runs: MemoryRunStore;
  events: GuardEvent[];
  /** The MCP endpoint. */
  mcp(request: Request): Promise<Response>;
  /** The MCP endpoint and the OAuth endpoints behind one function, routed by path. */
  fetch(request: Request): Promise<Response>;
  mcpUrl: string;
}

/** Not a secret: the example keeps everything in memory and forgets it on exit. */
const EXAMPLE_PEPPER = "example-pepper-not-a-secret-0123456789abcdef";

export function createHarbor(options: HarborOptions = {}): Harbor {
  const origin = options.origin ?? "http://localhost:8787";
  const world = createWorld();
  const credentials = new MemoryCredentialStore();
  const oauthStore = new MemoryOAuthStore();
  const audit = new MemoryAuditStore();
  const runs = new MemoryRunStore();
  const events: GuardEvent[] = [];

  const guard: Guard = createGuard({
    brand: "harbor",
    scopes: HARBOR_SCOPES,
    directory: world.directory,
    credentials,
    audit,
    runs,
    pepper: EXAMPLE_PEPPER,
    agents: HARBOR_AGENTS,
    oauth: {
      store: oauthStore,
      issuer: origin,
      resource: `${origin}/mcp`,
      redirects: { allowLoopback: true, exact: ["https://client.example.test/callback"] },
    },
    sanitize: { redactors: [redactEmails] },
    now: options.now,
    onEvent: (event) => events.push(event),
    ...options.overrides,
  });

  const mcp = createMcpHandler(guard, {
    name: "harbor",
    version: "0.1.0",
    tools: harborTools(world, () => guard),
    instructions: (actor) => harborInstructions(actor.kind),
    clientIp: options.clientIp,
  });
  const oauth = createOAuthHandler(guard, { clientIp: options.clientIp });

  return {
    world,
    guard,
    credentials,
    oauthStore,
    audit,
    runs,
    events,
    mcp,
    mcpUrl: `${origin}/mcp`,
    async fetch(request) {
      const handled = await oauth(request);
      if (handled) return handled;
      if (new URL(request.url).pathname === "/mcp") return mcp(request);
      return new Response(null, { status: 404 });
    },
  };
}
