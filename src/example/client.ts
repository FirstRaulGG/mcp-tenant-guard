// An MCP client wired straight to the example's handler: real protocol, no socket.

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

import type { Harbor } from "./app.js";

export interface ToolAnswer {
  isError: boolean;
  /** The parsed JSON body of the result. */
  body: Record<string, unknown>;
  /** The body exactly as the model receives it. */
  text: string;
}

export interface HarborClient {
  instructions: string | undefined;
  toolNames(): Promise<string[]>;
  tools(): Promise<{ name: string; annotations?: Record<string, unknown> }[]>;
  call(name: string, args?: Record<string, unknown>): Promise<ToolAnswer>;
  close(): Promise<void>;
}

/** Sends one raw request to the example, as a client with this token would. */
export function rawRequest(harbor: Harbor, token: string | null, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  if (token) headers.set("authorization", `Bearer ${token}`);
  return harbor.fetch(new Request(harbor.mcpUrl, { method: "POST", ...init, headers }));
}

export async function connect(harbor: Harbor, token: string): Promise<HarborClient> {
  const transport = new StreamableHTTPClientTransport(new URL(harbor.mcpUrl), {
    requestInit: { headers: { authorization: `Bearer ${token}` } },
    fetch: (input, init) => harbor.fetch(new Request(input, init)),
  });
  const client = new Client({ name: "example-client", version: "0.1.0" });
  await client.connect(transport);

  return {
    instructions: client.getInstructions(),
    async tools() {
      return (await client.listTools()).tools.map((tool) => ({ name: tool.name, annotations: tool.annotations }));
    },
    async toolNames() {
      return (await client.listTools()).tools.map((tool) => tool.name).sort();
    },
    async call(name, args = {}) {
      const result = await client.callTool({ name, arguments: args });
      const content = result.content as { type: string; text?: string }[];
      const text = content[0]?.text ?? "";
      let body: Record<string, unknown>;
      try {
        body = JSON.parse(text) as Record<string, unknown>;
      } catch {
        // Protocol-level errors (an unknown tool, bad arguments) arrive as plain text.
        body = { error: text };
      }
      return { isError: result.isError === true, body, text };
    },
    close: () => client.close(),
  };
}
