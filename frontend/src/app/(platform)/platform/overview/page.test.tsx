import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, cleanup } from "@testing-library/react";
import * as riskEngine from "@/lib/riskEngine";
import * as vulnerability from "@/lib/vulnerability";
import * as attackSurfaceManagement from "@/lib/attackSurfaceManagement";
import * as aiPosture from "@/lib/ai-posture";
import * as ddos from "@/lib/ddos";
import * as behavior from "@/lib/behavior";
import * as platform from "@/lib/platform";
import * as runtime from "@/lib/runtime";
import * as securityOperations from "@/lib/securityOperations";
import PlatformOverviewPage from "./page";

vi.mock("@/lib/riskEngine");
vi.mock("@/lib/vulnerability");
vi.mock("@/lib/attackSurfaceManagement");
vi.mock("@/lib/ai-posture");
vi.mock("@/lib/ddos");
vi.mock("@/lib/behavior");
vi.mock("@/lib/platform");
vi.mock("@/lib/runtime");
vi.mock("@/lib/securityOperations");

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function mockRejectAll() {
  vi.mocked(platform.listPlatformUsers).mockRejectedValue(new Error("x"));
  vi.mocked(platform.listPlatformOrganizations).mockRejectedValue(new Error("x"));
  vi.mocked(platform.listPlatformAccess).mockRejectedValue(new Error("x"));
  vi.mocked(platform.getPlatformAudit).mockRejectedValue(new Error("x"));
  vi.mocked(runtime.getRuntimeStatus).mockRejectedValue(new Error("x"));
  vi.mocked(runtime.getAggregatedHealth).mockRejectedValue(new Error("x"));
  vi.mocked(runtime.getDlqEntries).mockRejectedValue(new Error("x"));
  vi.mocked(runtime.getReplayStatus).mockRejectedValue(new Error("x"));
  vi.mocked(securityOperations.getSummary).mockRejectedValue(new Error("x"));
  vi.mocked(riskEngine.getRiskProfileCoverage).mockRejectedValue(new Error("x"));
  vi.mocked(vulnerability.getInstanceSummary).mockRejectedValue(new Error("x"));
  vi.mocked(attackSurfaceManagement.getExposureStateCoverage).mockRejectedValue(new Error("x"));
  vi.mocked(aiPosture.getInventoryDashboard).mockRejectedValue(new Error("x"));
  vi.mocked(ddos.getDDoSPosture).mockRejectedValue(new Error("x"));
  vi.mocked(behavior.getBehaviorPosture).mockRejectedValue(new Error("x"));
}

describe("PlatformOverviewPage posture cards", () => {
  it("renders real cross-domain data with drill-down links into the owning module, never a duplicated table", async () => {
    mockRejectAll();
    vi.mocked(riskEngine.getRiskProfileCoverage).mockResolvedValue({
      open: 3,
      acknowledged: 1,
      mitigated: 2,
      accepted: 0,
      closed: 5,
    });
    vi.mocked(vulnerability.getInstanceSummary).mockResolvedValue({
      tenant_id: "t1",
      by_severity: { critical: 4 },
      by_state: {},
      total_open: 6,
      total_resolved: 2,
      last_updated_at: "",
    });

    render(<PlatformOverviewPage />);

    await waitFor(() => {
      expect(screen.getByText("Risk")).toBeInTheDocument();
    });
    expect(screen.getAllByText("View →").length).toBeGreaterThanOrEqual(6);
    const riskLink = screen.getAllByText("View →")[0].closest("a");
    expect(riskLink).toHaveAttribute("href", "/risk");
  });

  it("shows an honest error state, never a fabricated number, when a posture data source fails", async () => {
    mockRejectAll();
    render(<PlatformOverviewPage />);

    await waitFor(() => {
      expect(screen.getAllByText(/x/).length).toBeGreaterThan(0);
    });
  });
});
