import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, cleanup } from "@testing-library/react";
import ComplianceOverviewPage from "./page";

vi.mock("@/components/cc", async () => {
  const actual = await vi.importActual<typeof import("@/components/cc")>(
    "@/components/cc"
  );
  return actual;
});

vi.mock("@/lib/compliance", async () => {
  const actual = await vi.importActual<typeof import("@/lib/compliance")>(
    "@/lib/compliance"
  );
  return {
    ...actual,
    getConsoleOverview: vi.fn(),
    listConsoleTimeline: vi.fn(),
  };
});

import { getConsoleOverview, listConsoleTimeline } from "@/lib/compliance";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("ComplianceOverviewPage", () => {
  it("shows loading state", () => {
    vi.mocked(getConsoleOverview).mockReturnValue(new Promise(() => {}));
    vi.mocked(listConsoleTimeline).mockReturnValue(new Promise(() => {}));
    render(<ComplianceOverviewPage />);
    expect(screen.getByText(/Loading compliance posture/i)).toBeInTheDocument();
  });

  it("renders posture and KPI strip from overview summary", async () => {
    vi.mocked(getConsoleOverview).mockResolvedValue({
      profiles: 1,
      open_periods: 1,
      assessments_total: 10,
      validated_count: 4,
      posture_score: 55,
      posture_band: "moderate",
      status_counts: { technically_validated: 4, not_assessed: 6 },
      evidence_link_count: 3,
      assessments_with_evidence: 2,
      recommendation_counts: {
        recommended: 3,
        accepted: 1,
        linked: 1,
        rejected: 0,
        total: 5,
      },
      acceptance_pct: 100,
      framework_progress: [
        { framework_key: "soc2", total: 10, validated: 4, coverage_pct: 40 },
      ],
      open_period_summaries: [
        {
          id: "per1",
          name: "Q1",
          framework_key: "soc2",
          period_start: "2026-01-01T00:00:00Z",
          period_end: "2026-03-31T00:00:00Z",
          status: "open",
        },
      ],
      recently_validated: [],
    });
    vi.mocked(listConsoleTimeline).mockResolvedValue({
      items: [],
      total: 0,
      limit: 12,
      offset: 0,
    });

    render(<ComplianceOverviewPage />);

    await waitFor(() => {
      expect(screen.getByText("Compliance Operations")).toBeInTheDocument();
    });
    expect(screen.getByLabelText(/Posture score/i)).toBeInTheDocument();
    expect(screen.getByText("Q1")).toBeInTheDocument();
    expect(screen.getByText(/Open Periods/i)).toBeInTheDocument();
  });
});
