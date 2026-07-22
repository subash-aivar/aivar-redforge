import { api } from "@/lib/api";

export interface ThreatHuntCandidate {
  candidate_id: string;
  tenant_id: string;
  status: string;
  confidence_score: number;
  detection_rule_format: string;
  technique_coverage: string[];
  anomaly_signal_count: number;
}

export function listCandidates(): Promise<ThreatHuntCandidate[]> {
  return api.get<ThreatHuntCandidate[]>("/api/v1/threat-hunt/candidates");
}

export function promoteCandidate(
  candidateId: string,
  promotedBy: string,
  promotedRuleVersionId: string
): Promise<ThreatHuntCandidate> {
  return api.post<ThreatHuntCandidate>(
    `/api/v1/threat-hunt/candidates/${candidateId}/promote`,
    { promoted_by: promotedBy, promoted_rule_version_id: promotedRuleVersionId }
  );
}

export function rejectCandidate(
  candidateId: string,
  rejectedBy: string,
  rejectionReason: string
): Promise<ThreatHuntCandidate> {
  return api.post<ThreatHuntCandidate>(
    `/api/v1/threat-hunt/candidates/${candidateId}/reject`,
    { rejected_by: rejectedBy, rejection_reason: rejectionReason }
  );
}

export function statusTone(status: string): "critical" | "high" | "warning" | "ok" | "neutral" {
  switch (status.toLowerCase()) {
    case "promoted":
      return "ok";
    case "rejected":
      return "neutral";
    case "pending_review":
    case "pending":
      return "warning";
    default:
      return "neutral";
  }
}
