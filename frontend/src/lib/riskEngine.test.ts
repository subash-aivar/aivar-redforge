import { describe, it, expect, vi, beforeEach } from "vitest";
import { api } from "@/lib/api";
import { getRiskProfileCoverage, RISK_PROFILE_STATUSES } from "@/lib/riskEngine";

vi.mock("@/lib/api");

beforeEach(() => {
  vi.clearAllMocks();
});

describe("getRiskProfileCoverage", () => {
  it("issues one filtered request per real backend status and reports each real count", async () => {
    vi.mocked(api.get).mockImplementation((url: string) => {
      const status = new URL(url, "http://x").searchParams.get("status");
      const counts: Record<string, number> = {
        open: 4,
        acknowledged: 2,
        mitigated: 1,
        accepted: 0,
        closed: 9,
      };
      return Promise.resolve({ items: [], count: counts[status ?? ""] ?? 0 });
    });

    const coverage = await getRiskProfileCoverage();

    expect(api.get).toHaveBeenCalledTimes(RISK_PROFILE_STATUSES.length);
    expect(coverage).toEqual({
      open: 4,
      acknowledged: 2,
      mitigated: 1,
      accepted: 0,
      closed: 9,
    });
  });
});
