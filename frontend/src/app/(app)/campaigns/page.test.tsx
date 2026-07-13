import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { api } from "@/lib/api";
import CampaignsPage from "./page";
import {
  CampaignDetailView,
  toCanonicalNodeState,
  type CampaignDetail,
} from "./campaign-graph";

vi.mock("@/lib/api", () => ({
  api: { get: vi.fn(), post: vi.fn() },
}));

function makeDetail(
  graph_nodes: CampaignDetail["graph_nodes"]
): CampaignDetail {
  return {
    campaign_id: "c-1",
    organization_id: "org-1",
    target_id: "t-1",
    state: "completed",
    goal_achieved: true,
    objective_name: "jailbreak",
    total_nodes: graph_nodes.length,
    nodes_executed: graph_nodes.length,
    completed_nodes: 0,
    failed_nodes: 0,
    blocked_nodes: 0,
    intelligence_confidence: 0.5,
    duration_ms: 100,
    failure_reason: null,
    created_at: new Date(0).toISOString(),
    graph_nodes,
    graph_edges: [],
  };
}

describe("toCanonicalNodeState", () => {
  const canonical = [
    "PENDING", "READY", "RUNNING", "COMPLETED",
    "FAILED", "BLOCKED", "SKIPPED",
  ];

  it.each(canonical)("maps %s to itself", (state) => {
    expect(toCanonicalNodeState(state)).toBe(state);
  });

  it.each(canonical)("is case-insensitive for %s", (state) => {
    expect(toCanonicalNodeState(state.toLowerCase())).toBe(state);
  });

  it("maps an unrecognized state to UNKNOWN", () => {
    expect(toCanonicalNodeState("SOME_NEW_STATE_FROM_FUTURE_API")).toBe("UNKNOWN");
  });

  it("maps null to UNKNOWN", () => {
    expect(toCanonicalNodeState(null)).toBe("UNKNOWN");
  });

  it("maps undefined to UNKNOWN", () => {
    expect(toCanonicalNodeState(undefined)).toBe("UNKNOWN");
  });

  it("maps empty string to UNKNOWN", () => {
    expect(toCanonicalNodeState("")).toBe("UNKNOWN");
  });

  it("never silently maps an unknown state to a known one", () => {
    const knownSet = new Set(canonical);
    expect(knownSet.has(toCanonicalNodeState("TOTALLY_UNRECOGNIZED"))).toBe(false);
  });
});

describe("CampaignDetailView graph rendering", () => {
  const canonical = [
    "PENDING", "READY", "RUNNING", "COMPLETED",
    "FAILED", "BLOCKED", "SKIPPED",
  ];

  it.each(canonical)("renders node state %s", (state) => {
    const detail = makeDetail([
      { id: "node-1", state, attack_category: "jailbreak" },
    ]);
    render(<CampaignDetailView detail={detail} onClose={() => {}} />);
    expect(screen.getByText(state)).toBeInTheDocument();
  });

  it("renders UNKNOWN for an unrecognized API state", () => {
    const detail = makeDetail([
      { id: "node-1", state: "SOME_FUTURE_STATE" },
    ]);
    render(<CampaignDetailView detail={detail} onClose={() => {}} />);
    expect(screen.getByText("UNKNOWN")).toBeInTheDocument();
  });

  it("renders zero-node state with an explicit empty message, not a blank graph", () => {
    const detail = makeDetail([]);
    render(<CampaignDetailView detail={detail} onClose={() => {}} />);
    expect(screen.getByText(/No attack nodes recorded/i)).toBeInTheDocument();
  });

  it("renders a failure_reason banner when the campaign failed", () => {
    const detail = { ...makeDetail([]), failure_reason: "target endpoint unreachable" };
    render(<CampaignDetailView detail={detail} onClose={() => {}} />);
    expect(screen.getByText("target endpoint unreachable")).toBeInTheDocument();
  });

  it("renders per-node failure_reason without leaking it onto other nodes", () => {
    const detail = makeDetail([
      { id: "node-1", state: "FAILED", failure_reason: "rate limited" },
      { id: "node-2", state: "COMPLETED" },
    ]);
    render(<CampaignDetailView detail={detail} onClose={() => {}} />);
    expect(screen.getByText("rate limited")).toBeInTheDocument();
  });
});

describe("CampaignsPage API error handling", () => {
  it("surfaces an API error truthfully instead of a silent empty state", async () => {
    vi.mocked(api.get).mockRejectedValueOnce(new Error("Network request failed"));
    render(<CampaignsPage />);
    await waitFor(() => {
      expect(screen.getByText("Network request failed")).toBeInTheDocument();
    });
  });
});
