import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, cleanup, fireEvent, within } from "@testing-library/react";
import * as aiPosture from "@/lib/ai-posture";
import AIPosturePage from "./page";

vi.mock("@/lib/ai-posture");

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function mockBase() {
  vi.mocked(aiPosture.getInventoryDashboard).mockResolvedValue({
    tenant_id: "t1",
    assets: [{ asset_id: "asset-1", ai_system_kind: "rag_system", lifecycle_state: "Registered" }],
    last_scan_at: null,
    configured_discovery_sources: [],
    coverage_scope: "full",
  });
  vi.mocked(aiPosture.getShadowDiscoveryReport).mockResolvedValue({
    tenant_id: "t1",
    alerts: [],
    partial_scans: [],
  });
}

describe("AIPosturePage", () => {
  it("shows honest empty states for risk register, supply chain, and deviations when nothing has been computed yet", async () => {
    mockBase();
    vi.mocked(aiPosture.getRiskRegister).mockResolvedValue({ tenant_id: "t1", entries: [], empty: true });
    vi.mocked(aiPosture.getSupplyChainIntegrity).mockResolvedValue({ tenant_id: "t1", models: [], empty: true });
    vi.mocked(aiPosture.getAgentDeviations).mockResolvedValue({ tenant_id: "t1", deviations: [], empty: true });

    render(<AIPosturePage />);

    await waitFor(() => {
      expect(screen.getByText("No AI risk scores computed yet.")).toBeInTheDocument();
    });
    expect(screen.getByText("No model provenance facts recorded yet.")).toBeInTheDocument();
    expect(screen.getByText("No agent deviations recorded yet.")).toBeInTheDocument();
  });

  it("surfaces real cross-panel relationships (risk score, supply chain, deviations) for the clicked asset via the shared asset_id", async () => {
    mockBase();
    vi.mocked(aiPosture.getRiskRegister).mockResolvedValue({
      tenant_id: "t1",
      entries: [{ asset_id: "asset-1", composite_score: 8.1, score_input_version: "v1", computed_at: new Date(0).toISOString(), is_stale: false }],
    });
    vi.mocked(aiPosture.getSupplyChainIntegrity).mockResolvedValue({
      tenant_id: "t1",
      models: [
        {
          asset_id: "asset-1",
          provenance_id: "prov-1",
          integrity_status: "Verified",
          verification_method: "IndependentHash",
          tier_label: "IndependentHash",
          trust_delegation_note: "",
        },
      ],
    });
    vi.mocked(aiPosture.getAgentDeviations).mockResolvedValue({
      tenant_id: "t1",
      deviations: [
        { deviation_id: "dev-1", asset_id: "asset-1", deviation_type: "unauthorized_tool_use", severity: "high", review_state: "open" },
      ],
    });
    vi.mocked(aiPosture.getAsset).mockResolvedValue({
      asset_id: "asset-1",
      tenant_id: "t1",
      asset_ref_id: "ref-1",
      lifecycle_state: "Registered",
      registration_status: "approved",
      ai_system_kind: "rag_system",
      owner_id: "team-x",
      threat_profile_id: null,
      risk_score_snapshot_id: null,
      data_sensitivity: "high",
    });

    render(<AIPosturePage />);

    await waitFor(() => screen.getByText("rag_system"));
    fireEvent.click(screen.getByText("rag_system"));

    await waitFor(() => {
      expect(screen.getByRole("dialog")).toBeInTheDocument();
    });
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText(/8\.10/)).toBeInTheDocument();
    expect(within(dialog).getByText("Verified")).toBeInTheDocument();
    expect(within(dialog).getByText("unauthorized_tool_use")).toBeInTheDocument();
  });
});
