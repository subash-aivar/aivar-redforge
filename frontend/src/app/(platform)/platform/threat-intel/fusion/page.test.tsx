import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, cleanup, fireEvent } from "@testing-library/react";

vi.mock("next/link", () => ({
  default: ({ href, children, ...rest }: { href: string; children: React.ReactNode }) =>
    <a href={href} {...rest}>{children}</a>,
}));

vi.mock("@/lib/fusion", () => ({
  listFusedIndicators: vi.fn(),
  listFusionWeights: vi.fn(),
  updateFusionWeight: vi.fn(),
  runFusion: vi.fn(),
  confidenceColor: () => "border-emerald-800 bg-emerald-950/50 text-emerald-300",
  riskStateColor: () => "border-red-800 bg-red-950/60 text-red-300",
  lifecycleColor: () => "border-emerald-800 bg-emerald-950/50 text-emerald-300",
  INDICATOR_TYPES: ["technique", "vulnerability"],
  INDICATOR_TYPE_LABELS: { technique: "ATT&CK Technique", vulnerability: "Vulnerability" },
}));

import * as fusion from "@/lib/fusion";
import FusionExplorerPage from "./page";

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

const indicator = {
  id: "ind-1",
  canonical_key: "T1059",
  indicator_type: "technique",
  display_name: "Command and Scripting Interpreter",
  lifecycle: "active",
  confidence: "high",
  risk_state: "critical",
  winner_source_system: "mitre_attack",
  source_count: 3,
  metadata: {},
  valid_from: "2024-01-01T00:00:00Z",
  valid_until: null,
};

describe("FusionExplorerPage", () => {
  it("shows loading then renders fused indicator", async () => {
    vi.mocked(fusion.listFusionWeights).mockResolvedValue({ mitre_attack: 1.0, nvd_cve: 0.8 });
    vi.mocked(fusion.listFusedIndicators).mockResolvedValue([indicator]);
    render(<FusionExplorerPage />);
    await waitFor(() =>
      expect(screen.getByText("Command and Scripting Interpreter")).toBeInTheDocument(),
    );
    expect(screen.getByText("T1059")).toBeInTheDocument();
  });

  it("shows error banner when indicators API fails", async () => {
    vi.mocked(fusion.listFusionWeights).mockResolvedValue({});
    vi.mocked(fusion.listFusedIndicators).mockRejectedValue(new Error("fail"));
    render(<FusionExplorerPage />);
    await waitFor(() =>
      expect(screen.getByText("Failed to load fused indicators.")).toBeInTheDocument(),
    );
  });

  it("shows empty state when no indicators", async () => {
    vi.mocked(fusion.listFusionWeights).mockResolvedValue({});
    vi.mocked(fusion.listFusedIndicators).mockResolvedValue([]);
    render(<FusionExplorerPage />);
    await waitFor(() =>
      expect(screen.getByText("No fused indicators found for this filter.")).toBeInTheDocument(),
    );
  });

  it("shows fusion weights from API", async () => {
    vi.mocked(fusion.listFusionWeights).mockResolvedValue({ mitre_attack: 0.95 });
    vi.mocked(fusion.listFusedIndicators).mockResolvedValue([]);
    render(<FusionExplorerPage />);
    await waitFor(() => expect(screen.getByText("mitre_attack")).toBeInTheDocument());
    expect(screen.getByText("0.95")).toBeInTheDocument();
  });

  it("shows success banner after run fusion", async () => {
    vi.mocked(fusion.listFusionWeights).mockResolvedValue({});
    vi.mocked(fusion.listFusedIndicators).mockResolvedValue([]);
    vi.mocked(fusion.runFusion).mockResolvedValue({
      indicators_created: 10,
      indicators_updated: 5,
      relationships_upserted: 20,
      stub_indicators_created: 0,
      no_evidence_count: 1,
    });
    render(<FusionExplorerPage />);
    await waitFor(() => screen.getByText("Run Fusion"));
    fireEvent.click(screen.getByText("Run Fusion"));
    await waitFor(() =>
      expect(screen.getByText(/Fusion complete/)).toBeInTheDocument(),
    );
    expect(screen.getByText(/created 10/)).toBeInTheDocument();
  });

  it("shows fusion error banner when run fails", async () => {
    vi.mocked(fusion.listFusionWeights).mockResolvedValue({});
    vi.mocked(fusion.listFusedIndicators).mockResolvedValue([]);
    vi.mocked(fusion.runFusion).mockRejectedValue(new Error("fail"));
    render(<FusionExplorerPage />);
    await waitFor(() => screen.getByText("Run Fusion"));
    fireEvent.click(screen.getByText("Run Fusion"));
    await waitFor(() =>
      expect(screen.getByText("Fusion run failed — check platform logs.")).toBeInTheDocument(),
    );
  });
});
