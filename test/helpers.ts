import { expect } from "vitest";

import { createHarbor } from "../src/example/app.js";
import type { Harbor, HarborOptions } from "../src/example/app.js";
import { issueCredential } from "../src/guard/issue.js";
import type { IssueRequest } from "../src/guard/issue.js";

export interface TestHarbor extends Harbor {
  /** Moves the clock forward. */
  advance(ms: number): void;
  clock(): Date;
}

export function harbor(options: HarborOptions = {}): TestHarbor {
  let time = Date.UTC(2025, 2, 5, 9, 0, 0);
  const now = () => new Date(time);
  const instance = createHarbor({ now, ...options });
  return Object.assign(instance, {
    advance(ms: number) {
      time += ms;
    },
    clock: now,
  });
}

/** Issues a credential and returns the plaintext token. Fails the test if issuing is refused. */
export async function issue(h: Harbor, request: Partial<IssueRequest> & Pick<IssueRequest, "kind" | "userId">): Promise<string> {
  const result = await issueCredential(h.guard, { name: "test token", ...request });
  if (!result.ok) throw new Error(`could not issue: ${result.reason}`);
  return result.token;
}

export const MARA = "user_mara";
export const TOMAS = "user_tomas";
export const NELL = "user_nell";
export const JUN = "user_jun";
export const ODILE = "user_odile";
export const FERNHILL = "shop_fernhill";
export const QUAYSIDE = "shop_quayside";
export const LARKSPUR = "shop_larkspur";

export const advisorToken = (h: Harbor, scopes: string[] = ["orders:read", "stock:read"]) =>
  issue(h, { kind: "advisor", userId: MARA, scopes });

export const ownerToken = (h: Harbor, userId = NELL, scopes: string[] = ["orders:read", "stock:read"]) =>
  issue(h, { kind: "owner", userId, tenantId: FERNHILL, scopes });

export const agentToken = (h: Harbor, tenantId = FERNHILL) =>
  issue(h, { kind: "agent", userId: MARA, tenantId, agentName: "restock" });

export function expectRefused(answer: { isError: boolean; body: Record<string, unknown> }, status: number): void {
  expect(answer.isError).toBe(true);
  expect(answer.body.status).toBe(status);
}

/** Characters that cannot be typed safely into a source file. */
export const RLO = String.fromCharCode(0x202e);
export const LINE_SEPARATOR = String.fromCharCode(0x2028);
export const ZERO_WIDTH_SPACE = String.fromCharCode(0x200b);
