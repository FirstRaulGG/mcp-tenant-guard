// The shape of what a tool returns, and how a failure is reported to the model.

/** Statuses a tool may report. Anything else is turned into 500. */
export const TOOL_STATUSES = [400, 403, 404, 409, 413, 422, 429, 500, 503, 504] as const;
export type ToolStatus = (typeof TOOL_STATUSES)[number];

/** Thrown by a tool, or by the guard, to refuse a call with a message the model may read. */
export class ToolError extends Error {
  readonly status: ToolStatus;

  constructor(status: ToolStatus, message: string) {
    super(message);
    this.name = "ToolError";
    this.status = status;
  }
}

/** The MCP `CallToolResult` shape, kept local so the core does not depend on the SDK. */
export interface ToolResult {
  [key: string]: unknown;
  content: { type: "text"; text: string }[];
  isError?: boolean;
}

export function okResult(payload: unknown): ToolResult {
  return { content: [{ type: "text", text: JSON.stringify(payload, null, 2) }] };
}

/**
 * A refusal is a normal tool result with `isError`, not a protocol error: the model can read why
 * and choose what to do. The message is short and written for that reader.
 */
export function errorResult(status: ToolStatus, message: string): ToolResult {
  return { isError: true, content: [{ type: "text", text: JSON.stringify({ error: message, status }) }] };
}

/** Reads the status back from a result. 200 for success; 500 when an error body cannot be read. */
export function statusOf(result: ToolResult): number {
  if (!result.isError) return 200;
  try {
    const body = JSON.parse(result.content[0]?.text ?? "") as { status?: unknown };
    return typeof body.status === "number" ? body.status : 500;
  } catch {
    return 500;
  }
}

/** Default ceiling for one serialized result: about 25k tokens of JSON. */
export const DEFAULT_MAX_RESULT_BYTES = 100_000;

export function byteLength(text: string): number {
  return Buffer.byteLength(text, "utf8");
}

/**
 * Refuses a result that is too large instead of cutting it. A cut in the middle of JSON hands the
 * model half a list with no sign that it is half; a refusal tells it to ask for less.
 */
export function enforceResultSize(result: ToolResult, maxBytes: number): ToolResult {
  const size = byteLength(result.content[0]?.text ?? "");
  if (size <= maxBytes) return result;
  return errorResult(413, `Result too large (${size} bytes, limit ${maxBytes}). Ask for fewer rows or a narrower period.`);
}

// ---------------------------------------------------------------------------
// Annotations
// ---------------------------------------------------------------------------

export interface ToolHints {
  readOnlyHint: boolean;
  destructiveHint: boolean;
  idempotentHint: boolean;
  openWorldHint: boolean;
}

/**
 * What a tool does to the world, as the four MCP hints. All four are always stated: a client that
 * falls back to the protocol defaults would treat an unannotated read as a destructive write.
 */
export type ToolEffect = "read" | "external_read" | "propose" | "write" | "overwrite";

export const TOOL_HINTS: Readonly<Record<ToolEffect, ToolHints>> = {
  read: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  /** A read that queries a live system outside the host application. */
  external_read: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  /** Creates a request for a person to decide. Calling it twice creates two. */
  propose: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  /** Adds or updates with history kept. Safe to repeat with the same request id. */
  write: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  /** Replaces state with nothing kept of what was there. */
  overwrite: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
};
