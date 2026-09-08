import { describe, it, expect, vi, beforeEach } from "vitest";
import { api } from "@/lib/api";
import { getExposureStateCoverage, EXPOSURE_STATES } from "@/lib/attackSurfaceManagement";

vi.mock("@/lib/api");

beforeEach(() => {
  vi.clearAllMocks();
});

describe("getExposureStateCoverage", () => {
  it("issues one filtered request per real backend exposure state and reports each real count", async () => {
    vi.mocked(api.get).mockImplementation((url: string) => {
      const state = new URL(url, "http://x").searchParams.get("exposure_state");
      const counts: Record<string, number> = {
        unknown: 1,
        not_exposed: 12,
        internet_facing: 5,
        exposed_high_risk: 2,
      };
      return Promise.resolve({ items: [], count: counts[state ?? ""] ?? 0 });
    });

    const coverage = await getExposureStateCoverage();

    expect(api.get).toHaveBeenCalledTimes(EXPOSURE_STATES.length);
    expect(coverage).toEqual({
      unknown: 1,
      not_exposed: 12,
      internet_facing: 5,
      exposed_high_risk: 2,
    });
  });
});
