import { describe, expect, it } from "vitest";

import { runDemo } from "../src/demo.js";

describe("the demo", () => {
  it("passes every check it prints", async () => {
    const { output, failures } = await runDemo();
    expect(failures).toBe(0);
    expect(output).not.toContain("FAIL ");
    expect(output).toContain("All checks passed.");
  });
});
