import { api } from "@/lib/api";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ExposureRecord {
  record_id: string;
  tenant_id: string;
  asset_ref_id: string;
  source_type: string;
  status: string;
  base_score: number;
  computed_score: number;
  amplifiers: Record<string, number>;
  created_at: string;
  updated_at: string;
}

export interface ExposureScore {
  asset_ref_id: string;
  final_score: number;
  base_aggregate: number;
  amplifier_aggregate: number;
  active_records: number;
  computed_at: string;
}

export interface ExposureProfile {
  tenant_id: string;
  total_assets: number;
  avg_score: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
}

export interface ExposureWeights {
  weights: Record<string, number>;
  tenant_id: string;
  updated_at: string | null;
}

export interface ExposureScopeResult {
  assets: Array<{
    asset_ref_id: string;
    score: number;
    active_records: number;
    asset_kind: string;
  }>;
  total: number;
}

export interface ThreatTargeting {
  actors: Array<{
    threat_actor_ref: string;
    targeted_cve_ids: string[];
    targeted_asset_classes: string[];
    targeted_techniques: string[];
    targeting_confidence: string;
  }>;
}

// ─── API ─────────────────────────────────────────────────────────────────────

export function getExposureProfile(): Promise<ExposureProfile> {
  return api.get<ExposureProfile>("/api/v1/exposure/profile");
}

export function getExposureWeights(): Promise<ExposureWeights> {
  return api.get<ExposureWeights>("/api/v1/exposure/weights");
}

export function getExposureRecord(recordId: string): Promise<ExposureRecord> {
  return api.get<ExposureRecord>(`/api/v1/exposure/records/${recordId}`);
}

export function getAssetRecords(assetRefId: string, status?: string): Promise<ExposureRecord[]> {
  const q = status ? `?status=${status}` : "";
  return api.get<ExposureRecord[]>(`/api/v1/exposure/assets/${assetRefId}/records${q}`);
}

export function getAssetScore(assetRefId: string): Promise<ExposureScore | null> {
  return api.get<ExposureScore | null>(`/api/v1/exposure/assets/${assetRefId}/score`);
}

export function queryExposureScope(params: {
  max_assets?: number;
  min_exposure_score?: number;
  amplifier_filter?: string[];
  asset_kind_filter?: string[];
  include_stale_scores?: boolean;
}): Promise<ExposureScopeResult> {
  return api.post<ExposureScopeResult>("/api/v1/exposure/scope/query", params);
}

export function suppressRecord(recordId: string, justification: string, suppressedBy: string): Promise<ExposureRecord> {
  return api.post<ExposureRecord>(`/api/v1/exposure/records/${recordId}/suppress`, {
    justification,
    suppressed_by: suppressedBy,
  });
}

export function configureWeights(weights: Record<string, number>, rationale: string, changedBy: string): Promise<ExposureWeights> {
  return api.put<ExposureWeights>("/api/v1/exposure/weights", {
    weights,
    change_rationale: rationale,
    changed_by: changedBy,
  });
}

export function getThreatTargeting(): Promise<ThreatTargeting> {
  return api.get<ThreatTargeting>("/api/v1/exposure/threat-intel/targeting");
}

export function getExposureHealth(): Promise<{ status: string; pipeline_paused: boolean }> {
  return api.get("/api/v1/exposure/health");
}
