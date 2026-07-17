import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";
import RecommendationQueueInner from "./RecommendationQueueInner";

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(),
}));

vi.mock("@/lib/compliance", async () => {
  const actual = await vi.importActual<typeof import("@/lib/compliance")>(
    "@/lib/compliance"
  );
  return {
    ...actual,
    acceptRecommendation: vi.fn(),
    rejectRecommendation: vi.fn(),
    linkRecommendation: vi.fn(),
    generateRecommendations: vi.fn(),
    getConsoleOverview: vi.fn(),
    listConsoleRecommendations: vi.fn(),
  };
});

import {
  acceptRecommendation,
  getConsoleOverview,
  listConsoleRecommendations,
} from "@/lib/compliance";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const rec = {
  id: "rec-1",
  organization_id: "o1",
  batch_id: "b1",
  assessment_id: "a1",
  period_id: "per1",
  requirement_id: "req1",
  framework_key: "soc2",
  primary_reference: {
    source_kind: "validation_evidence",
    source_entity_id: "evid-1",
  },
  candidates: [
    {
      reference: {
        source_kind: "validation_evidence",
        source_entity_id: "evid-1",
      },
      raw_score: 0.9,
      rationale: "match",
      signals: ["peer_confirmed"],
    },
  ],
  confidence: "high",
  score: 0.91,
  rationale: "Strong overlap with control evidence",
  status: "recommended",
  dedup_key: "k1",
  decision: null,
  linked_evidence_id: null,
  created_by: "u1",
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

describe("RecommendationQueueInner", () => {
  it("renders queue rows and opens drawer actions with accessible controls", async () => {
    vi.mocked(getConsoleOverview).mockResolvedValue({
      profiles: 0,
      open_periods: 1,
      assessments_total: 0,
      validated_count: 0,
      posture_score: 0,
      posture_band: "critical",
      status_counts: {},
      evidence_link_count: 0,
      assessments_with_evidence: 0,
      recommendation_counts: {
        recommended: 1,
        accepted: 0,
        linked: 0,
        rejected: 0,
        total: 1,
      },
      acceptance_pct: 0,
      framework_progress: [
        { framework_key: "soc2", total: 1, validated: 0, coverage_pct: 0 },
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
    vi.mocked(listConsoleRecommendations).mockResolvedValue({
      items: [rec],
      total: 1,
      limit: 50,
      offset: 0,
    });
    vi.mocked(acceptRecommendation).mockResolvedValue({
      ...rec,
      status: "accepted",
    });

    render(<RecommendationQueueInner />);

    await waitFor(() => {
      expect(
        screen.getByRole("heading", { name: /Recommendation Review Queue/i })
      ).toBeInTheDocument();
    });
    expect(screen.getByText(/Strong overlap/i)).toBeInTheDocument();

    fireEvent.click(screen.getByText(/Strong overlap/i));
    expect(
      screen.getByRole("heading", { name: /Evidence Recommendation/i })
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^Accept$/i })).toBeEnabled();
    expect(screen.getByRole("button", { name: /^Reject$/i })).toBeEnabled();
    expect(screen.getByRole("button", { name: /^Link$/i })).toBeDisabled();
  });

  it("shows empty state when queue has no rows", async () => {
    vi.mocked(getConsoleOverview).mockResolvedValue({
      profiles: 0,
      open_periods: 0,
      assessments_total: 0,
      validated_count: 0,
      posture_score: 0,
      posture_band: "critical",
      status_counts: {},
      evidence_link_count: 0,
      assessments_with_evidence: 0,
      recommendation_counts: {
        recommended: 0,
        accepted: 0,
        linked: 0,
        rejected: 0,
        total: 0,
      },
      acceptance_pct: 0,
      framework_progress: [],
      open_period_summaries: [],
      recently_validated: [],
    });
    vi.mocked(listConsoleRecommendations).mockResolvedValue({
      items: [],
      total: 0,
      limit: 50,
      offset: 0,
    });

    render(<RecommendationQueueInner />);
    await waitFor(() => {
      expect(
        screen.getByText(/No recommendations in this view/i)
      ).toBeInTheDocument();
    });
  });
});
