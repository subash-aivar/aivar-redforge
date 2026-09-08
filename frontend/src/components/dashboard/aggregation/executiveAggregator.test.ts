import { describe, it, expect, vi, beforeEach } from "vitest";
import * as exposureApi from "@/lib/exposure";
import * as riskEngine from "@/lib/riskEngine";
import * as complianceApi from "@/lib/compliance";
import * as aiPostureApi from "@/lib/ai-posture";
import * as attackSurfaceManagement from "@/lib/attackSurfaceManagement";
import { executiveAggregator } from "@/components/dashboard/aggregation/executiveAggregator";
import type { WidgetSpec } from "@/components/dashboard/layout/DashboardCompositionEngine";

vi.mock("@/lib/exposure");
vi.mock("@/lib/riskEngine");
vi.mock("@/lib/compliance");
vi.mock("@/lib/ai-posture");
vi.mock("@/lib/attackSurfaceManagement");

function kpi(widgets: WidgetSpec[], id: string) {
  const w = widgets.find((w) => w.type === "kpi" && w.viewModel.id === id);
  return w && w.type === "kpi" ? w.viewModel.value : undefined;
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(exposureApi.getExposureProfile).mockRejectedValue(new Error("not mocked"));
  vi.mocked(riskEngine.listRiskProfiles).mockRejectedValue(new Error("not mocked"));
  vi.mocked(complianceApi.listProfiles).mockRejectedValue(new Error("not mocked"));
  vi.mocked(aiPostureApi.getInventoryDashboard).mockRejectedValue(new Error("not mocked"));
  vi.mocked(attackSurfaceManagement.listAssets).mockRejectedValue(new Error("not mocked"));
});

describe("executiveAggregator", () => {
  it("never throws even when every source is unavailable", async () => {
    const spec = await executiveAggregator.load({ timeRange: "30d", filters: {} });
    expect(spec.id).toBe("executive-overview");
  });

  it("shows an awaiting-integration panel instead of a fabricated chart when no exposure profile exists", async () => {
    const spec = await executiveAggregator.load({ timeRange: "30d", filters: {} });
    const panel = spec.widgets.find(
      (w) => w.type === "awaiting-integration" && w.viewModel.id === "exposure-distribution"
    );
    expect(panel).toBeDefined();
  });

  it("computes real business KPIs from real risk-profile and exposure data", async () => {
    vi.mocked(exposureApi.getExposureProfile).mockResolvedValue({
      tenant_id: "t1",
      asset_scores: { "asset-1": 8.5, "asset-2": 4.3 },
      tenant_exposure_score: 6.4,
      recomputing: false,
      recomputation_failed_at: null,
      metadata: {},
    });
    vi.mocked(riskEngine.listRiskProfiles).mockResolvedValue({
      items: [
        { profile_id: "p1", status: "accepted", composite_score: 3, contributions: [] } as never,
        { profile_id: "p2", status: "open", composite_score: 7, contributions: [] } as never,
      ],
      count: 2,
    });

    const spec = await executiveAggregator.load({ timeRange: "30d", filters: {} });
    expect(kpi(spec.widgets, "avg-exposure-score")).toBe("6.4");
    expect(kpi(spec.widgets, "avg-risk-score")).toBe("5.00");
    expect(kpi(spec.widgets, "open-risk")).toBe(1);
    expect(kpi(spec.widgets, "accepted-risk")).toBe(1);

    const chart = spec.widgets.find(
      (w) => w.type === "chart" && w.viewModel.id === "exposure-distribution"
    );
    expect(chart).toBeDefined();
  });

  it("shows the awaiting-integration panel (not a crash or a fabricated chart) when a fresh tenant's exposure profile has no scored assets yet", async () => {
    // Regression test: the real `/exposure/profile` endpoint for a
    // brand-new tenant returns {tenant_id, asset_scores:{}, ...} — a
    // real object (not a rejection), previously read via
    // `.avg_score`/`.critical_count` fields that never existed on this
    // DTO at all, crashing the whole executive dashboard.
    vi.mocked(exposureApi.getExposureProfile).mockResolvedValue({
      tenant_id: "t1",
      asset_scores: {},
      tenant_exposure_score: 0,
      recomputing: false,
      recomputation_failed_at: null,
      metadata: {},
    });

    const spec = await executiveAggregator.load({ timeRange: "30d", filters: {} });
    expect(kpi(spec.widgets, "avg-exposure-score")).toBe("0.0");
    const panel = spec.widgets.find(
      (w) => w.type === "awaiting-integration" && w.viewModel.id === "exposure-distribution"
    );
    expect(panel).toBeDefined();
  });
});
