/**
 * Security Correlation / Attack Surface API client — M9.
 *
 * Read-only plus explicit `evaluate` only. No client function exists
 * to create a correlation, set its evidence_state, or forge an
 * external exposure classification — the server-controlled rule
 * registry is the only producer of correlation truth.
 */
import { api } from "./api";

export interface SecurityCorrelation {
  id: string;
  organization_id: string;
  stable_rule_id: string;
  rule_version: number;
  evidence_state: string;
  lifecycle: string;
  title: string;
  summary: string;
  operator_action: string;
  entity_ids: string[];
  condition_ids: string[];
  first_observed_at: string;
  last_observed_at: string;
  resolved_at: string | null;
}

export interface CorrelationEvaluationSummary {
  rules_evaluated: number;
  matched: number;
  created: number;
  updated: number;
  resolved: number;
  evaluated_at: string;
}

export interface AttackSurfaceSummary {
  assets_with_active_conditions: number;
  assets_with_multiple_active_conditions: number;
  active_correlations: number;
  external_classification_breakdown: Record<string, number>;
  evidence_state_breakdown: Record<string, number>;
}

export interface AssetExposureSummary {
  asset_id: string;
  asset_name: string;
  asset_kind: string;
  external_classification: string;
  active_condition_count: number;
  observed_condition_count: number;
  inferred_condition_count: number;
  validated_condition_count: number;
  highest_active_severity: string;
  active_source_categories: string[];
  sensitive_service_count: number;
  active_correlation_count: number;
  last_condition_observed_at: string | null;
}

export interface ListCorrelationsParams {
  lifecycle?: string;
  stable_rule_id?: string;
  evidence_state?: string;
  limit?: number;
  offset?: number;
}

export async function evaluateCorrelations(): Promise<CorrelationEvaluationSummary> {
  return api.post<CorrelationEvaluationSummary>("/api/v1/security-correlations/evaluate");
}

export async function listSecurityCorrelations(
  params: ListCorrelationsParams = {}
): Promise<SecurityCorrelation[]> {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") query.set(key, String(value));
  }
  const qs = query.toString();
  return api.get<SecurityCorrelation[]>(
    `/api/v1/security-correlations${qs ? `?${qs}` : ""}`
  );
}

export async function getSecurityCorrelation(id: string): Promise<SecurityCorrelation> {
  return api.get<SecurityCorrelation>(`/api/v1/security-correlations/${id}`);
}

export async function getAttackSurfaceSummary(): Promise<AttackSurfaceSummary> {
  return api.get<AttackSurfaceSummary>("/api/v1/attack-surface/summary");
}

export async function getAssetExposureSummary(assetId: string): Promise<AssetExposureSummary> {
  return api.get<AssetExposureSummary>(`/api/v1/attack-surface/assets/${assetId}`);
}
