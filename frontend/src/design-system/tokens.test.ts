import { describe, expect, it } from "vitest";
import { statusToTone } from "@/design-system/tokens";

describe("statusToTone", () => {
  it.each([
    ["healthy", "success"],
    ["ok", "success"],
    ["ready", "success"],
    ["degraded", "warning"],
    ["pending", "warning"],
    ["unhealthy", "danger"],
    ["failed", "danger"],
    ["something-unrecognized", "neutral"],
  ] as const)("maps %s to %s", (status, expected) => {
    expect(statusToTone(status)).toBe(expected);
  });

  it("is case-insensitive", () => {
    expect(statusToTone("HEALTHY")).toBe("success");
  });
});
