// What happens around a tool: audit, limits, time, size, failure.

import { describe, expect, it } from "vitest";
import { z } from "zod";

import { statusOf } from "../src/core/result.js";
import type { ToolResult } from "../src/core/result.js";
import { connect } from "../src/example/client.js";
import { authenticate } from "../src/guard/authenticate.js";
import { assertTools, defineTool, executeTool } from "../src/guard/tool.js";
import type { AnyTool } from "../src/guard/tool.js";
import { FERNHILL, LARKSPUR, MARA, QUAYSIDE, advisorToken, agentToken, expectRefused, harbor, ownerToken } from "./helpers.js";
import type { TestHarbor } from "./helpers.js";

async function run(h: TestHarbor, token: string, tool: AnyTool, args: unknown, signal = new AbortController().signal): Promise<ToolResult> {
  const actor = await authenticate(h.guard, `Bearer ${token}`);
  if (!actor) throw new Error("token refused");
  return executeTool(h.guard, { actor, traceId: "trace-1", signal, runId: null }, tool, args);
}

const body = (result: ToolResult) => JSON.parse(result.content[0]!.text) as Record<string, unknown>;

const echo = defineTool({
  name: "echo_stock",
  title: "Echo",
  description: "Returns its argument.",
  input: { text: z.string().optional() },
  scope: "stock:read",
  effect: "read",
  audit: [],
  async handler({ args, target }) {
    return { tenantId: target!.tenantId, text: args.text ?? "" };
  },
});

describe("audit", () => {
  it("writes one row per call, with the declared arguments and never the result", async () => {
    const h = harbor();
    const client = await connect(h, await ownerToken(h));
    await client.call("read_orders", { limit: 2, status: "new" });

    expect(h.audit.entries).toHaveLength(1);
    expect(h.audit.entries[0]).toMatchObject({
      tool: "read_orders", tenantId: FERNHILL, userId: "user_nell", actorKind: "owner", outcome: "ok", status: 200,
      params: { limit: 2, status: "new" },
    });
    expect(JSON.stringify(h.audit.entries)).not.toContain("Wren");
  });

  it("keeps free text out of the log unless the tool declared it", async () => {
    const h = harbor();
    const client = await connect(h, await agentToken(h));
    await client.call("propose_restock", { sku: "MUG-01", quantity: 4, reason: "a sentence nobody asked to store" });
    expect(h.audit.entries[0]!.params).toEqual({ sku: "MUG-01", quantity: 4 });
  });

  it("names the delegating person on an agent's rows", async () => {
    const h = harbor();
    const client = await connect(h, await agentToken(h));
    await client.call("read_stock");
    expect(h.audit.entries[0]).toMatchObject({ userId: MARA, actorKind: "agent", agentName: "restock" });
  });

  it("does not read when the audit row cannot be written", async () => {
    const h = harbor();
    let handlerRan = false;
    const probe = defineTool({ ...echo, name: "probe", handler: async () => ((handlerRan = true), { ok: true }) });
    h.audit.failOpen = true;

    const result = await run(h, await ownerToken(h), probe, {});
    expect(statusOf(result)).toBe(503);
    expect(handlerRan).toBe(false);
  });

  it("still answers when only the closing update fails, leaving the row open", async () => {
    const h = harbor();
    h.audit.failClose = true;
    const result = await run(h, await ownerToken(h), echo, {});
    expect(statusOf(result)).toBe(200);
    expect(h.audit.entries[0]!.outcome).toBe("open");
    expect(h.events.some((event) => event.type === "audit_close_failed")).toBe(true);
  });

  it("leaves a durable trace of a refused cross-tenant attempt", async () => {
    const h = harbor();
    const client = await connect(h, await advisorToken(h));
    await client.call("read_orders", { limit: 5, tenantId: LARKSPUR });
    expect(h.audit.entries).toHaveLength(1);
    expect(h.audit.entries[0]).toMatchObject({ outcome: "denied", status: 404, tenantId: LARKSPUR, tool: "read_orders", userId: MARA });
  });

  it("records a failing tool as an error, with its status", async () => {
    const h = harbor();
    const client = await connect(h, await agentToken(h));
    await client.call("propose_restock", { sku: "NOPE", quantity: 1, reason: "missing sku" });
    expect(h.audit.entries[0]).toMatchObject({ outcome: "error", status: 404 });
  });
});

describe("the checks around a tool", () => {
  it("enforces scope and visibility even when the tool is reached directly", async () => {
    const h = harbor();
    const [, , , , , setOrderStatus] = (await import("../src/example/tools.js")).harborTools(h.world, () => h.guard);
    const args = { orderId: "F-1004", status: "packed" };

    expectRefused({ isError: true, body: body(await run(h, await ownerToken(h), setOrderStatus!, args)) }, 403);
    expectRefused({ isError: true, body: body(await run(h, await agentToken(h), setOrderStatus!, args)) }, 403);
    expect(h.world.orders[FERNHILL]!.find((o) => o.id === "F-1004")!.status).toBe("new");
    expect(h.audit.entries.every((entry) => entry.outcome === "denied")).toBe(true);
  });

  it("refuses unknown and malformed arguments", async () => {
    const h = harbor();
    expect(statusOf(await run(h, await ownerToken(h), echo, { text: 42 }))).toBe(400);
  });

  it("charges by cost, and tells the caller when to come back", async () => {
    const h = harbor({ overrides: { limits: { costPerCredential: { limit: 5, windowMs: 60_000 } } } });
    const client = await connect(h, await agentToken(h));
    expect((await client.call("propose_restock", { sku: "MUG-01", quantity: 1, reason: "first" })).isError).toBe(false);
    const refused = await client.call("propose_restock", { sku: "MUG-01", quantity: 1, reason: "second" });
    expectRefused(refused, 429);
    expect(String(refused.body.error)).toMatch(/Try again in \d+ seconds/);
    expect(h.world.proposals).toHaveLength(1);
  });

  it("does not start a call once the request's time is spent", async () => {
    const h = harbor();
    const spent = new AbortController();
    spent.abort();
    let handlerRan = false;
    const probe = defineTool({ ...echo, name: "probe", handler: async () => ((handlerRan = true), { ok: true }) });
    expect(statusOf(await run(h, await ownerToken(h), probe, {}, spent.signal))).toBe(504);
    expect(handlerRan).toBe(false);
  });

  it("gives up on a call that outlives the budget", async () => {
    const h = harbor();
    const budget = new AbortController();
    const slow = defineTool({ ...echo, name: "slow", handler: () => new Promise(() => {}) });
    const pending = run(h, await ownerToken(h), slow, {}, budget.signal);
    setTimeout(() => budget.abort(), 5);
    const result = await pending;
    expect(statusOf(result)).toBe(504);
    expect(String(body(result).error)).toContain("fewer rows");
  });

  it("refuses a result that is too large, rather than cutting it", async () => {
    const h = harbor({ overrides: { maxResultBytes: 500, sanitize: { maxLength: 10_000 } } });
    const result = await run(h, await ownerToken(h), echo, { text: "x".repeat(2000) });
    expect(statusOf(result)).toBe(413);
    expect(result.content[0]!.text).not.toContain("xxxx");
  });

  it("answers an unexpected failure with a reference, and keeps the detail for the operator", async () => {
    const h = harbor();
    const broken = defineTool({
      ...echo,
      name: "broken",
      handler: async () => {
        throw new Error("connection string postgres://secret-host/db refused");
      },
    });
    const result = await run(h, await ownerToken(h), broken, {});
    expect(statusOf(result)).toBe(500);
    expect(result.content[0]!.text).toContain("trace-1");
    expect(result.content[0]!.text).not.toContain("secret-host");
    expect(JSON.stringify(h.events)).toContain("secret-host");
  });

  it("never puts arguments or results in the events it emits", async () => {
    const h = harbor();
    const client = await connect(h, await ownerToken(h));
    await client.call("read_orders", { limit: 50 });
    const toolEvents = h.events.filter((event) => event.type === "tool");
    expect(toolEvents).toHaveLength(1);
    expect(Object.keys(toolEvents[0]!.detail ?? {}).sort()).toEqual(["credentialId", "durationMs", "status", "tenantId", "tool", "userId"]);
    expect(JSON.stringify(h.events)).not.toContain("Wren");
  });
});

describe("declaring tools", () => {
  it("refuses a write tool behind a read scope, and other mismatches, at start-up", () => {
    const h = harbor();
    expect(() => assertTools(h.guard, [{ ...echo, effect: "write" }])).toThrow(/cannot be gated/);
    expect(() => assertTools(h.guard, [{ ...echo, scope: "made:up" }])).toThrow(/unknown scope/);
    expect(() => assertTools(h.guard, [{ ...echo, scope: null }])).toThrow(/needs a scope/);
    expect(() => assertTools(h.guard, [echo, echo])).toThrow(/twice/);
    expect(() => assertTools(h.guard, [{ ...echo, input: { tenantId: z.string() } }])).toThrow(/added by the guard/);
    expect(() => assertTools(h.guard, [echo])).not.toThrow();
  });
});

describe("runs", () => {
  it("stamps an agent's calls with its open run, and stops when the run ends", async () => {
    const h = harbor();
    const token = await agentToken(h);
    const client = await connect(h, token);

    await client.call("read_stock");
    const started = await client.call("start_run", { trigger: "schedule", clientRequestId: "night-2025-03-05" });
    const runId = started.body.runId as string;
    await client.call("read_stock");
    await client.call("propose_restock", { sku: "BOWL-03", quantity: 12, reason: "none on hand" });
    const ended = await client.call("end_run", { runId, status: "done", summary: "one proposal" });
    await client.call("read_stock");

    expect(ended.body.status).toBe("done");
    const byTool = h.audit.entries.map((entry) => [entry.tool, entry.runId]);
    expect(byTool).toEqual([
      ["read_stock", null],
      ["start_run", null],
      ["read_stock", runId],
      ["propose_restock", runId],
      ["end_run", runId],
      ["read_stock", null],
    ]);
    // The summary is free text: stored on the run, absent from the audit log.
    expect(JSON.stringify(h.audit.entries)).not.toContain("one proposal");
    expect(h.runs.runs[0]!.summary).toBe("one proposal");
  });

  it("returns the same run for a repeated request, and never reopens a closed one", async () => {
    const h = harbor();
    const client = await connect(h, await agentToken(h));
    const first = await client.call("start_run", { trigger: "manual", clientRequestId: "request-0001" });
    const again = await client.call("start_run", { trigger: "manual", clientRequestId: "request-0001" });
    expect(again.body).toMatchObject({ runId: first.body.runId, replay: true, status: "running" });

    await client.call("end_run", { runId: first.body.runId, status: "failed" });
    const afterClose = await client.call("start_run", { trigger: "manual", clientRequestId: "request-0001" });
    expect(afterClose.body).toMatchObject({ runId: first.body.runId, replay: true, status: "failed" });
    const closedAgain = await client.call("end_run", { runId: first.body.runId, status: "done" });
    expect(closedAgain.body.status).toBe("failed");
    expect(h.runs.runs).toHaveLength(1);
  });

  it("closes the previous run when a new one starts", async () => {
    const h = harbor();
    const client = await connect(h, await agentToken(h));
    const first = await client.call("start_run", { trigger: "manual", clientRequestId: "request-0001" });
    await client.call("start_run", { trigger: "manual", clientRequestId: "request-0002" });
    expect(h.runs.runs.find((run) => run.id === first.body.runId)).toMatchObject({ status: "failed", summary: "superseded by a newer run" });
  });

  it("cannot see or close another credential's run", async () => {
    const h = harbor();
    const fernhill = await connect(h, await agentToken(h, FERNHILL));
    const quayside = await connect(h, await agentToken(h, QUAYSIDE));
    const started = await fernhill.call("start_run", { trigger: "manual", clientRequestId: "request-0001" });

    const foreign = await quayside.call("end_run", { runId: started.body.runId, status: "done" });
    const missing = await quayside.call("end_run", { runId: "no-such-run", status: "done" });
    expectRefused(foreign, 404);
    expect(foreign.text).toBe(missing.text);
    expect(h.runs.runs[0]!.status).toBe("running");
  });

  it("is not offered to people", async () => {
    const h = harbor();
    expect(await (await connect(h, await advisorToken(h))).toolNames()).not.toContain("start_run");
    expect(await (await connect(h, await ownerToken(h))).toolNames()).not.toContain("start_run");
  });
});
