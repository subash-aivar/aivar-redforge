/**
 * Presentation helpers for the Compliance Operations Console.
 * Pure formatting / aggregation — no API calls, no domain decisions.
 */

import type {
  ControlAssessment,
  EvidenceRecommendation,
  RecommendationStatistics,
} from "./compliance";

export const CONTROL_STATUS_ORDER = [
  "not_assessed",
  "collecting_evidence",
  "pending_confirmation",
  "technically_validated",
] as const;

export function statusLabel(status: string): string {
  return status.replace(/_/g, " ");
}

export function controlStatusTone(
  status: string
): "default" | "danger" | "warning" | "ok" {
  switch (status) {
    case "technically_validated":
      return "ok";
    case "pending_confirmation":
      return "warning";
    case "collecting_evidence":
      return "default";
    case "not_assessed":
      return "danger";
    default:
      return "default";
  }
}

export function controlStatusPillClass(status: string): string {
  switch (status) {
    case "technically_validated":
      return "border-emerald-800 bg-emerald-950/50 text-emerald-300";
    case "pending_confirmation":
      return "border-amber-800 bg-amber-950/50 text-amber-300";
    case "collecting_evidence":
      return "border-sky-800 bg-sky-950/50 text-sky-300";
    case "not_assessed":
      return "border-gray-700 bg-gray-800/60 text-gray-400";
    default:
      return "border-gray-700 bg-gray-800/60 text-gray-300";
  }
}

export function recommendationStatusPillClass(status: string): string {
  switch (status) {
    case "linked":
      return "border-emerald-800 bg-emerald-950/50 text-emerald-300";
    case "accepted":
      return "border-sky-800 bg-sky-950/50 text-sky-300";
    case "rejected":
      return "border-red-800 bg-red-950/50 text-red-300";
    case "recommended":
      return "border-amber-800 bg-amber-950/50 text-amber-300";
    default:
      return "border-gray-700 bg-gray-800/60 text-gray-300";
  }
}

export function confidencePillClass(confidence: string): string {
  switch (confidence) {
    case "very_high":
    case "high":
      return "border-emerald-800 bg-emerald-950/50 text-emerald-300";
    case "medium":
      return "border-amber-800 bg-amber-950/50 text-amber-300";
    case "low":
    case "very_low":
      return "border-orange-800 bg-orange-950/50 text-orange-300";
    default:
      return "border-gray-700 bg-gray-800/60 text-gray-300";
  }
}

export function sourceKindLabel(kind: string): string {
  return kind.replace(/_/g, " ");
}

/** Posture score 0–100 from assessment status mix (UI aggregation only). */
export function computePostureScore(assessments: ControlAssessment[]): {
  score: number;
  band: string;
  validated: number;
  total: number;
} {
  const total = assessments.length;
  if (total === 0) {
    return { score: 0, band: "at_risk", validated: 0, total: 0 };
  }
  const weights: Record<string, number> = {
    not_assessed: 0,
    collecting_evidence: 0.35,
    pending_confirmation: 0.65,
    technically_validated: 1,
  };
  let sum = 0;
  let validated = 0;
  for (const a of assessments) {
    sum += weights[a.status] ?? 0.25;
    if (a.status === "technically_validated") validated += 1;
  }
  const score = Math.round((sum / total) * 100);
  const band =
    score >= 80 ? "strong" : score >= 55 ? "moderate" : score >= 30 ? "at_risk" : "critical";
  return { score, band, validated, total };
}

export function statusDistribution(
  assessments: ControlAssessment[]
): { label: string; value: number }[] {
  const counts = new Map<string, number>();
  for (const s of CONTROL_STATUS_ORDER) counts.set(s, 0);
  for (const a of assessments) {
    counts.set(a.status, (counts.get(a.status) ?? 0) + 1);
  }
  return [...counts.entries()].map(([label, value]) => ({
    label: statusLabel(label),
    value,
  }));
}

export function evidenceCoverage(assessments: ControlAssessment[]): {
  withEvidence: number;
  withoutEvidence: number;
  linkCount: number;
} {
  let withEvidence = 0;
  let linkCount = 0;
  for (const a of assessments) {
    linkCount += a.evidence_links.length;
    if (a.evidence_links.length > 0) withEvidence += 1;
  }
  return {
    withEvidence,
    withoutEvidence: assessments.length - withEvidence,
    linkCount,
  };
}

export function acceptanceRate(stats: RecommendationStatistics): number {
  const decided = stats.accepted + stats.rejected + stats.linked;
  if (decided === 0) return 0;
  return Math.round(((stats.accepted + stats.linked) / decided) * 100);
}

export type TimelineEvent = {
  id: string;
  at: string;
  kind: string;
  title: string;
  detail: string;
  href?: string;
};

export function composeTimeline(input: {
  assessments: ControlAssessment[];
  recommendations: EvidenceRecommendation[];
}): TimelineEvent[] {
  const events: TimelineEvent[] = [];

  for (const a of input.assessments) {
    events.push({
      id: `assessment-created-${a.id}`,
      at: a.created_at,
      kind: "assessment",
      title: `Assessment ${statusLabel(a.status)}`,
      detail: `${a.framework_key} · requirement ${a.requirement_id}`,
      href: `/compliance/assessments/${a.id}`,
    });
    if (a.updated_at !== a.created_at) {
      events.push({
        id: `assessment-updated-${a.id}-${a.updated_at}`,
        at: a.updated_at,
        kind: "status",
        title: `Status · ${statusLabel(a.status)}`,
        detail: `Control assessment ${a.id}`,
        href: `/compliance/assessments/${a.id}`,
      });
    }
    for (const link of a.evidence_links) {
      events.push({
        id: `evidence-${a.id}-${link.evidence_id}-${link.confirmed_at}`,
        at: link.confirmed_at,
        kind: "evidence",
        title: "Evidence confirmed",
        detail: `${link.evidence_id} · ${link.confirmed_by}`,
        href: `/compliance/assessments/${a.id}`,
      });
    }
  }

  for (const r of input.recommendations) {
    events.push({
      id: `rec-${r.id}-${r.status}-${r.updated_at}`,
      at: r.updated_at,
      kind: "recommendation",
      title: `Recommendation ${statusLabel(r.status)}`,
      detail: `${r.confidence} · ${r.primary_reference.source_kind}:${r.primary_reference.source_entity_id}`,
      href: `/compliance/recommendations?id=${r.id}`,
    });
  }

  return events.sort((a, b) => (a.at < b.at ? 1 : a.at > b.at ? -1 : 0));
}

export type EvidenceExplorerRow = {
  id: string;
  category:
    | "confirmed"
    | "recommended"
    | "investigation_evidence"
    | "threat_intelligence"
    | "cloud_scan"
    | "other";
  source_kind: string;
  entity_id: string;
  assessment_id: string | null;
  recommendation_id: string | null;
  status: string;
  confidence: string | null;
  updated_at: string;
  rationale: string;
};

export function composeEvidenceRows(input: {
  assessments: ControlAssessment[];
  recommendations: EvidenceRecommendation[];
}): EvidenceExplorerRow[] {
  const rows: EvidenceExplorerRow[] = [];

  for (const a of input.assessments) {
    for (const link of a.evidence_links) {
      rows.push({
        id: `confirmed-${a.id}-${link.evidence_id}`,
        category: "confirmed",
        source_kind: "confirmed_control_evidence",
        entity_id: link.evidence_id,
        assessment_id: a.id,
        recommendation_id: null,
        status: "confirmed",
        confidence: null,
        updated_at: link.confirmed_at,
        rationale: link.rationale || "Human-confirmed evidence link",
      });
    }
  }

  for (const r of input.recommendations) {
    const kind = r.primary_reference.source_kind;
    let category: EvidenceExplorerRow["category"] = "recommended";
    if (kind === "investigation_evidence") category = "investigation_evidence";
    else if (kind === "threat_intelligence") category = "threat_intelligence";
    else if (kind === "cloud_scan") category = "cloud_scan";
    else if (kind === "validation_evidence" || kind === "confirmed_control_evidence") {
      category = r.status === "linked" ? "confirmed" : "recommended";
    } else {
      category = "other";
    }
    rows.push({
      id: `rec-${r.id}`,
      category,
      source_kind: kind,
      entity_id: r.primary_reference.source_entity_id,
      assessment_id: r.assessment_id,
      recommendation_id: r.id,
      status: r.status,
      confidence: r.confidence,
      updated_at: r.updated_at,
      rationale: r.rationale,
    });
  }

  return rows.sort((a, b) => (a.updated_at < b.updated_at ? 1 : -1));
}

export function barColorForStatus(label: string): string {
  const key = label.replace(/ /g, "_");
  switch (key) {
    case "technically_validated":
      return "#34d399";
    case "pending_confirmation":
      return "#fbbf24";
    case "collecting_evidence":
      return "#38bdf8";
    case "not_assessed":
      return "#6b7280";
    default:
      return "#ef4444";
  }
}
