import { describe, it, expect, vi, beforeEach } from "vitest";
import { api } from "@/lib/api";
import { approveEnvelope, draftEnvelope, getAdvisories, suspendEnvelope } from "@/lib/aiGovernance";

vi.mock("@/lib/api");

beforeEach(() => {
  vi.clearAllMocks();
});

describe("aiGovernance client — real route regression coverage", () => {
  it("drafts an envelope on the real /envelopes route, not the dead /policies route", async () => {
    vi.mocked(api.post).mockResolvedValue({});
    await draftEnvelope({ asset_id: "asset-1" });
    expect(api.post).toHaveBeenCalledWith("/api/v1/ai-agent-governance/envelopes", { asset_id: "asset-1" });
  });

  it("approves an envelope with the real {approver_id} body shape", async () => {
    vi.mocked(api.post).mockResolvedValue({});
    await approveEnvelope("env-1", "analyst-1");
    expect(api.post).toHaveBeenCalledWith(
      "/api/v1/ai-agent-governance/envelopes/env-1/approve",
      { approver_id: "analyst-1" }
    );
  });

  it("suspends an envelope with the real {reason} body shape", async () => {
    vi.mocked(api.post).mockResolvedValue({});
    await suspendEnvelope("env-1", "compromised credentials");
    expect(api.post).toHaveBeenCalledWith(
      "/api/v1/ai-agent-governance/envelopes/env-1/suspend",
      { reason: "compromised credentials" }
    );
  });

  it("looks up advisories from the real route, not the dead /violations route", async () => {
    vi.mocked(api.get).mockResolvedValue([]);
    await getAdvisories("env-1");
    expect(api.get).toHaveBeenCalledWith("/api/v1/ai-agent-governance/envelopes/env-1/advisories");
  });
});
