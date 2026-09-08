import { describe, it, expect } from "vitest";
import { detectEditionMismatch, editionMismatchDiagnostic } from "@/lib/editionMismatch";

describe("detectEditionMismatch", () => {
  it("is not mismatched when both sides report full", () => {
    const info = detectEditionMismatch("full", "full");
    expect(info.mismatched).toBe(false);
  });

  it("is not mismatched when both sides report network_defense", () => {
    const info = detectEditionMismatch("network_defense", "network_defense");
    expect(info.mismatched).toBe(false);
  });

  it("is mismatched when frontend=full and backend=network_defense", () => {
    const info = detectEditionMismatch("full", "network_defense");
    expect(info.mismatched).toBe(true);
    expect(info.frontendEdition).toBe("full");
    expect(info.backendEdition).toBe("network_defense");
  });

  it("is mismatched when frontend=network_defense and backend=full", () => {
    const info = detectEditionMismatch("network_defense", "full");
    expect(info.mismatched).toBe(true);
  });

  it("fails open (not mismatched) when the backend value is missing/unreachable", () => {
    expect(detectEditionMismatch("full", undefined).mismatched).toBe(false);
    expect(detectEditionMismatch("full", null).mismatched).toBe(false);
    expect(detectEditionMismatch("full", "").mismatched).toBe(false);
  });
});

describe("editionMismatchDiagnostic", () => {
  it("names both editions and never includes secrets/env dumps", () => {
    const info = detectEditionMismatch("full", "network_defense");
    const message = editionMismatchDiagnostic(info);
    expect(message).toContain("full");
    expect(message).toContain("network_defense");
    expect(message.toLowerCase()).not.toContain("secret");
    expect(message.toLowerCase()).not.toContain("token");
  });
});
