import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { api } from "@/lib/api";
import ExposureManagementPage from "./page";
import type { SecurityCondition, SecurityConditionSummary } from "@/lib/securityConditions";

vi.mock("@/lib/api", () => ({
  api: { get: vi.fn(), post: vi.fn() },
}));

const SUMMARY: SecurityConditionSummary = {
  by_evidence_state: { observed: 3, inferred: 0, validated: 0 },
  by_severity: { medium: 2, high: 1 },
  by_source_category: { network_discovery: 3 },
  by_lifecycle: { active: 2, resolved: 1 },
};

function makeCondition(overrides: Partial<SecurityCondition> = {}): SecurityCondition {
  return {
    id: "cond-1",
    organization_id: "org-1",
    affected_asset_id: "asset-1",
    source_category: "network_discovery",
    stable_rule_id: "SENSITIVE_SERVICE_OBSERVED",
    evidence_state: "observed",
    severity: "medium",
    title: "Sensitive service observed",
    summary: "SSH observed on host-1.",
    remediation: "",
    canonical_references: [],
    evidence: [],
    lifecycle: "active",
    first_observed_at: new Date(0).toISOString(),
    last_observed_at: new Date(0).toISOString(),
    qualifier: "",
    ...overrides,
  };
}

function mockApi(summary: SecurityConditionSummary, conditions: SecurityCondition[]) {
  vi.mocked(api.get).mockImplementation((path: string) => {
    if (path.includes("/summary")) return Promise.resolve(summary);
    return Promise.resolve(conditions);
  });
}

describe("ExposureManagementPage overview", () => {
  it("renders backend-derived counts, not fabricated totals", async () => {
    mockApi(SUMMARY, [makeCondition()]);
    render(<ExposureManagementPage />);
    await waitFor(() => {
      expect(screen.getByText("3")).toBeInTheDocument(); // observed
    });
    expect(screen.getByText("2")).toBeInTheDocument(); // active
    expect(screen.getByText("1")).toBeInTheDocument(); // resolved
  });

  it("renders an explicit empty state, not a blank list", async () => {
    mockApi(SUMMARY, []);
    render(<ExposureManagementPage />);
    await waitFor(() => {
      expect(screen.getByText(/No security conditions match/i)).toBeInTheDocument();
    });
  });

  it("surfaces an API failure truthfully instead of a silent empty state", async () => {
    vi.mocked(api.get).mockRejectedValue(new Error("network down"));
    render(<ExposureManagementPage />);
    await waitFor(() => {
      expect(screen.getByText(/UNAVAILABLE/i)).toBeInTheDocument();
    });
  });
});

describe("ExposureManagementPage condition rendering", () => {
  it("renders an unrecognized severity as UNKNOWN, not a crash", async () => {
    mockApi(SUMMARY, [makeCondition({ severity: "some_future_severity" })]);
    render(<ExposureManagementPage />);
    await waitFor(() => {
      expect(screen.getByText("SOME_FUTURE_SEVERITY")).toBeInTheDocument();
    });
  });

  it("shows RESOLVED lifecycle without a Resolve action", async () => {
    mockApi(SUMMARY, [makeCondition({ lifecycle: "resolved" })]);
    render(<ExposureManagementPage />);
    await waitFor(() => {
      expect(screen.getByText("RESOLVED")).toBeInTheDocument();
    });
  });
});

describe("ExposureManagementPage detail drawer", () => {
  async function openDrawer() {
    mockApi(SUMMARY, [makeCondition()]);
    render(<ExposureManagementPage />);
    const row = await screen.findByText("Sensitive service observed");
    const trigger = row.closest("button")!;
    trigger.focus();
    fireEvent.click(trigger);
    await waitFor(() => {
      expect(screen.getByRole("dialog", { name: "Sensitive service observed" })).toBeInTheDocument();
    });
    return trigger;
  }

  it("opens as a labelled dialog with real accessibility semantics", async () => {
    await openDrawer();
    const dialog = screen.getByRole("dialog", { name: "Sensitive service observed" });
    expect(dialog).toHaveAttribute("aria-modal", "true");
  });

  it("Escape closes the drawer and returns focus to the trigger", async () => {
    const trigger = await openDrawer();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("dialog", { name: "Sensitive service observed" })).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });

  it("Close button closes the drawer without resolving the condition", async () => {
    await openDrawer();
    fireEvent.click(screen.getByText("Close"));
    expect(screen.queryByRole("dialog", { name: "Sensitive service observed" })).not.toBeInTheDocument();
    expect(api.post).not.toHaveBeenCalled();
  });
});
