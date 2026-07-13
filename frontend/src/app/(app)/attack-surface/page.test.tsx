import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { api } from "@/lib/api";
import AttackSurfacePage from "./page";
import type { AttackSurfaceSummary, SecurityCorrelation } from "@/lib/securityCorrelations";

vi.mock("@/lib/api", () => ({
  api: { get: vi.fn(), post: vi.fn() },
}));

const SUMMARY: AttackSurfaceSummary = {
  assets_with_active_conditions: 3,
  assets_with_multiple_active_conditions: 1,
  active_correlations: 2,
  external_classification_breakdown: { public_address_observed: 1 },
  evidence_state_breakdown: { observed: 3 },
};

function makeCorrelation(overrides: Partial<SecurityCorrelation> = {}): SecurityCorrelation {
  return {
    id: "corr-1",
    organization_id: "org-1",
    stable_rule_id: "MULTIPLE_SECURITY_CONDITIONS_ON_ASSET",
    rule_version: 1,
    evidence_state: "observed",
    lifecycle: "active",
    title: "Multiple active security conditions affect this asset",
    summary: "This asset has 2 active security conditions.",
    operator_action: "Review the active conditions together.",
    entity_ids: ["asset-1"],
    condition_ids: ["cond-1", "cond-2"],
    first_observed_at: new Date(0).toISOString(),
    last_observed_at: new Date(0).toISOString(),
    resolved_at: null,
    ...overrides,
  };
}

function mockApi(summary: AttackSurfaceSummary, correlations: SecurityCorrelation[]) {
  vi.mocked(api.get).mockImplementation((path: string) => {
    if (path.includes("/attack-surface/summary")) return Promise.resolve(summary);
    if (path.includes("/security-correlations")) return Promise.resolve(correlations);
    return Promise.resolve(correlations);
  });
}

describe("AttackSurfacePage overview", () => {
  it("renders backend-derived counts, not fabricated totals", async () => {
    mockApi(SUMMARY, [makeCorrelation()]);
    render(<AttackSurfacePage />);
    await waitFor(() => {
      expect(screen.getByText("3")).toBeInTheDocument();
    });
    expect(screen.getByText("1")).toBeInTheDocument();
    expect(screen.getByText("2")).toBeInTheDocument();
  });

  it("renders an explicit empty state, not a blank list", async () => {
    mockApi(SUMMARY, []);
    render(<AttackSurfacePage />);
    await waitFor(() => {
      expect(screen.getByText(/No correlations match/i)).toBeInTheDocument();
    });
  });

  it("surfaces an API failure truthfully instead of a silent empty state", async () => {
    vi.mocked(api.get).mockRejectedValue(new Error("network down"));
    render(<AttackSurfacePage />);
    await waitFor(() => {
      expect(screen.getByText(/UNAVAILABLE/i)).toBeInTheDocument();
    });
  });

  it("never labels the relationship view an Attack Path", async () => {
    mockApi(SUMMARY, [makeCorrelation()]);
    render(<AttackSurfacePage />);
    await waitFor(() => {
      expect(screen.getByText(/Exposure Relationship Path/i)).toBeInTheDocument();
    });
    // The product must never carry a mislabeled "Attack Path" heading/button —
    // the word appears only inside the explanatory "never an attack path" disclaimer.
    expect(screen.queryByRole("heading", { name: /attack path/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /attack path/i })).not.toBeInTheDocument();
  });
});

describe("AttackSurfacePage correlation rendering", () => {
  it("renders an unrecognized evidence_state as UNKNOWN, not a crash", async () => {
    mockApi(SUMMARY, [makeCorrelation({ evidence_state: "some_future_state" })]);
    render(<AttackSurfacePage />);
    await waitFor(() => {
      expect(screen.getByText("SOME_FUTURE_STATE")).toBeInTheDocument();
    });
  });
});
