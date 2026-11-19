// Runs: grouping what an unattended agent did into one piece of work.
//
// An agent opens a run, makes its calls, and closes it. Audited calls made in later requests,
// while the run is open, carry its id, so "what did the agent do last night" is one query. A run
// records work; it grants nothing and restricts nothing. Its boundaries are whatever the agent
// says they are: a run that is never closed keeps collecting calls until the next one starts.

import { z } from "zod";

import { ToolError } from "../core/result.js";
import { sanitizeText } from "../core/sanitize.js";
import type { AgentRun } from "../store/types.js";
import type { Guard } from "./guard.js";
import { defineTool, markBookkeeping } from "./tool.js";
import type { AnyTool } from "./tool.js";

const RUN_NOT_FOUND = "Run not found.";

function describeRun(run: AgentRun) {
  return {
    runId: run.id,
    agentName: run.agentName,
    tenantId: run.tenantId,
    status: run.status,
    startedAt: run.startedAt,
    endedAt: run.endedAt,
  };
}

/** The `start_run` and `end_run` tools. Empty when the guard has no run store. */
export function runTools(guard: Guard): AnyTool[] {
  const store = guard.runs;
  if (!store) return [];

  const startRun = defineTool({
    name: "start_run",
    title: "Start a run",
    description:
      "Opens a run: a named piece of unattended work. Calls made with this credential until the run is closed are attributed to it. Calling again with the same clientRequestId returns the same run.",
    input: {
      trigger: z.enum(["schedule", "manual", "webhook", "session"]).describe("What started this run."),
      clientRequestId: z.string().min(8).max(64).describe("An id chosen by the caller, unique per run. Makes a retry safe."),
    },
    scope: null,
    tenant: false,
    // A run belongs to one tenant and one agent, and only an agent credential is bound to both.
    actors: ["agent"],
    // It changes only the guard's own records: see `markBookkeeping`.
    effect: "write",
    audit: ["trigger", "clientRequestId"],
    async handler({ args, actor }) {
      const { agentName, tenantId } = actor;
      if (!agentName || !tenantId) throw new ToolError(403, "Runs are opened with an agent credential.");

      const now = guard.now();
      const { run, created } = await store.insertOrGet({
        id: guard.newId(),
        credentialId: actor.credentialId,
        userId: actor.userId,
        tenantId,
        agentName,
        trigger: args.trigger,
        clientRequestId: args.clientRequestId,
        status: "running",
        summary: null,
        startedAt: now,
        endedAt: null,
      });
      // Only a new run closes the others: a retry of an old request must not kill the current one.
      if (created) await store.supersede(actor.credentialId, agentName, run.id, now);
      return { ...describeRun(run), replay: !created };
    },
  });

  const endRun = defineTool({
    name: "end_run",
    title: "End a run",
    description: "Closes a run with its outcome. Closing a run that is already closed returns it unchanged.",
    input: {
      runId: z.string().max(64).describe("The id returned by start_run."),
      status: z.enum(["done", "failed"]),
      summary: z.string().max(500).optional().describe("One or two sentences on what was done."),
    },
    scope: null,
    tenant: false,
    actors: ["agent"],
    effect: "write",
    // The summary is free text and stays out of the audit log.
    audit: ["runId", "status"],
    async handler({ args, actor }) {
      const run = await store.get(args.runId);
      // Another credential's run looks exactly like one that does not exist.
      if (!run || run.credentialId !== actor.credentialId) throw new ToolError(404, RUN_NOT_FOUND);
      if (run.status === "running") {
        const summary = args.summary ? sanitizeText(args.summary, { ...guard.sanitize, maxLength: 500 }) : null;
        await store.close(run.id, { status: args.status, summary, at: guard.now() });
      }
      const current = (await store.get(run.id)) ?? run;
      return describeRun(current);
    },
  });

  return [markBookkeeping(startRun), markBookkeeping(endRun)];
}

/** The id of the credential's open run, or null. A failed lookup never blocks the request. */
export async function openRunId(guard: Guard, credentialId: string): Promise<string | null> {
  if (!guard.runs) return null;
  try {
    return (await guard.runs.findRunning(credentialId))?.id ?? null;
  } catch {
    return null;
  }
}
