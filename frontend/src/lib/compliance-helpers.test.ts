import { describe, it, expect } from "vitest";
import {
  acceptanceRate,
  composeEvidenceRows,
  composeTimeline,
  computePostureScore,
  evidenceCoverage,
  statusDistribution,
  statusLabel,
} from "@/lib/compliance-helpers";
import type {
  ControlAssessment,
  EvidenceRecommendation,
  RecommendationStatistics,
} from "@/lib/compliance";

function assessment(
  overrides: Partial<ControlAssessment> = {}
): ControlAssessment {
  return {
    id: "a1",
    organization_id: "o1",
    profile_id: "p1",
    period_id: "per1",
    requirement_id: "req1",
    framework_key: "soc2",
    status: "not_assessed",
    evidence_links: [],
    notes: "",
    created_by: "u1",
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-02T00:00:00Z",
    ...overrides,
  };
}

function recommendation(
  overrides: Partial<EvidenceRecommendation> = {}
): EvidenceRecommendation {
  return {
    id: "r1",
    organization_id: "o1",
    batch_id: "b1",
    assessment_id: "a1",
    period_id: "per1",
    requirement_id: "req1",
    framework_key: "soc2",
    primary_reference: {
      source_kind: "validation_evidence",
      source_entity_id: "e1",
    },
    candidates: [
      {
        reference: {
          source_kind: "validation_evidence",
          source_entity_id: "e1",
        },
        raw_score: 0.9,
        rationale: "match",
        signals: ["unit"],
      },
    ],
    confidence: "high",
    score: 0.9,
    rationale: "strong",
    status: "recommended",
    dedup_key: "k",
    decision: null,
    linked_evidence_id: null,
    created_by: "u1",
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-03T00:00:00Z",
    ...overrides,
  };
}

describe("compliance-helpers", () => {
  it("formats status labels", () => {
    expect(statusLabel("technically_validated")).toBe("technically validated");
  });

  it("computes posture from assessment mix", () => {
    const result = computePostureScore([
      assessment({ status: "technically_validated" }),
      assessment({ id: "a2", status: "not_assessed" }),
    ]);
    expect(result.total).toBe(2);
    expect(result.validated).toBe(1);
    expect(result.score).toBe(50);
  });

  it("distributes statuses", () => {
    const dist = statusDistribution([
      assessment({ status: "collecting_evidence" }),
      assessment({ id: "a2", status: "collecting_evidence" }),
    ]);
    const collecting = dist.find((d) => d.label === "collecting evidence");
    expect(collecting?.value).toBe(2);
  });

  it("counts evidence coverage", () => {
    const cov = evidenceCoverage([
      assessment({
        evidence_links: [
          {
            evidence_id: "e1",
            confirmed_by: "u",
            confirmed_at: "2026-01-01T00:00:00Z",
            rationale: "",
          },
        ],
      }),
      assessment({ id: "a2" }),
    ]);
    expect(cov.withEvidence).toBe(1);
    expect(cov.linkCount).toBe(1);
  });

  it("computes acceptance rate", () => {
    const stats: RecommendationStatistics = {
      recommended: 2,
      accepted: 1,
      linked: 1,
      rejected: 2,
      total: 6,
    };
    expect(acceptanceRate(stats)).toBe(50);
  });

  it("composes timeline from assessments and recommendations", () => {
    const events = composeTimeline({
      assessments: [
        assessment({
          evidence_links: [
            {
              evidence_id: "e1",
              confirmed_by: "u",
              confirmed_at: "2026-01-04T00:00:00Z",
              rationale: "ok",
            },
          ],
        }),
      ],
      recommendations: [recommendation()],
    });
    expect(events.length).toBeGreaterThan(2);
    expect(events[0].at >= events[events.length - 1].at).toBe(true);
  });

  it("composes evidence explorer rows without inventing data", () => {
    const rows = composeEvidenceRows({
      assessments: [
        assessment({
          evidence_links: [
            {
              evidence_id: "e1",
              confirmed_by: "u",
              confirmed_at: "2026-01-04T00:00:00Z",
              rationale: "ok",
            },
          ],
        }),
      ],
      recommendations: [
        recommendation({
          primary_reference: {
            source_kind: "threat_intelligence",
            source_entity_id: "ti1",
          },
        }),
      ],
    });
    expect(rows.some((r) => r.category === "confirmed")).toBe(true);
    expect(rows.some((r) => r.category === "threat_intelligence")).toBe(true);
  });
});
