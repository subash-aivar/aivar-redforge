/**
 * Risk Engine API client — M48F.
 *
 * The frontend had no consumer for this backend context until now
 * (confirmed by grep before writing this file — zero references to
 * `/api/v1/risk-profiles` anywhere in `src/lib` or `src/app`). This
 * client exposes only what the SOC dashboard's KPI wall needs
 * (list/count); it is not a full risk-engine UI.
 */
import { api } from "@/lib/api";

export interface RiskContribution {
  dimension: string;
  normalized_score: number;
  source_context: string;
  source_id: string;
  computed_at: string;
  subject_reference: string | null;
}

export interface RiskProfile {
  profile_id: string;
  tenant_id: string;
  subject_reference: string;
  status: string;
  created_at: string;
  updated_at: string;
  composite_score: number | null;
  weight_profile_id: string | null;
  composite_computed_at: string | null;
  accepted_expires_at: string | null;
  contributions: RiskContribution[];
}

export interface ListRiskProfilesResponse {
  items: RiskProfile[];
  count: number;
}

export function listRiskProfiles(params: { status?: string; limit?: number } = {}): Promise<ListRiskProfilesResponse> {
  const query = new URLSearchParams();
  if (params.status) query.set("status", params.status);
  if (params.limit) query.set("limit", String(params.limit));
  const qs = query.toString();
  return api.get<ListRiskProfilesResponse>(`/api/v1/risk-profiles${qs ? `?${qs}` : ""}`);
}

/** Every value of the backend's `RiskProfileStatus` enum (risk_engine/domain/value_objects/enums.py). */
export const RISK_PROFILE_STATUSES = ["open", "acknowledged", "mitigated", "accepted", "closed"] as const;
export type RiskProfileStatus = (typeof RISK_PROFILE_STATUSES)[number];

/**
 * Coverage-by-status counts for the risk landing page. The list endpoint has
 * no aggregate/count-by-status route, so this issues one filtered request per
 * status (5 total) and reads each response's `count` — still real backend
 * data, not a client-side fabrication of a missing aggregate endpoint.
 */
export async function getRiskProfileCoverage(): Promise<Record<RiskProfileStatus, number>> {
  const results = await Promise.all(
    RISK_PROFILE_STATUSES.map((status) => listRiskProfiles({ status, limit: 1 }))
  );
  const coverage = {} as Record<RiskProfileStatus, number>;
  RISK_PROFILE_STATUSES.forEach((status, i) => {
    coverage[status] = results[i].count;
  });
  return coverage;
}
