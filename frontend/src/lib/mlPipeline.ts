import { api } from "@/lib/api";

// ─── Types ───────────────────────────────────────────────────────────────────

export const ML_MODEL_TYPES = ["ANOMALY_DETECTOR", "RISK_PREDICTOR", "COVERAGE_FORECASTER"] as const;
export type MLModelType = (typeof ML_MODEL_TYPES)[number];

export interface TrainingResult {
  model_id: string;
  status: string;
  algorithm: string;
  accuracy_metrics: Record<string, number>;
  failure_reason: string | null;
}

export interface ModelActionResult {
  model_id: string;
  status: string;
}

export interface ModelDetail {
  model_id: string;
  model_type: string;
  algorithm: string;
  status: string;
  accuracy_metrics: Record<string, number>;
  artifact_hash: string | null;
  psi_score: number | null;
}

export interface ModelSummary {
  model_id: string;
  model_type: string;
  status: string;
}

export interface GovernanceEntry {
  [key: string]: unknown;
}

export interface RiskSignal {
  signal_id?: string;
  asset_ref_id: string;
  score: number;
  expires_at: string;
  signal_type?: string;
}

export interface SignalsResult {
  status: string;
  reason?: string;
  signals: RiskSignal[];
}

export interface InferenceResult {
  status: string;
  reason?: string;
  count?: number;
  signals: RiskSignal[];
}

export interface DriftResult {
  psi: number;
  severe: boolean;
  status: string;
}

// ─── API ─────────────────────────────────────────────────────────────────────

export function scheduleTraining(body: {
  model_type: string;
  dataset_id?: string;
  training_rows?: Array<Record<string, unknown>>;
}): Promise<TrainingResult> {
  return api.post<TrainingResult>("/api/v1/ml-pipeline/models/train", body);
}

export function promoteModel(modelId: string, deployedBy: string): Promise<ModelActionResult> {
  return api.post<ModelActionResult>(`/api/v1/ml-pipeline/models/${modelId}/promote`, {
    deployed_by: deployedBy,
  });
}

export function deprecateModel(modelId: string, deprecatedBy: string): Promise<ModelActionResult> {
  return api.post<ModelActionResult>(`/api/v1/ml-pipeline/models/${modelId}/deprecate`, {
    deprecated_by: deprecatedBy,
  });
}

export function getModel(modelId: string): Promise<ModelDetail> {
  return api.get<ModelDetail>(`/api/v1/ml-pipeline/models/${modelId}`);
}

export function listModels(params?: { model_type?: string; status?: string }): Promise<ModelSummary[]> {
  const q = new URLSearchParams();
  if (params?.model_type) q.set("model_type", params.model_type);
  if (params?.status) q.set("status", params.status);
  const qs = q.toString();
  return api.get<ModelSummary[]>(`/api/v1/ml-pipeline/models${qs ? `?${qs}` : ""}`);
}

export function getGovernanceHistory(modelId: string): Promise<GovernanceEntry[]> {
  return api.get<GovernanceEntry[]>(`/api/v1/ml-pipeline/models/${modelId}/governance`);
}

export function getSignals(params?: { asset_ref_id?: string; signal_type?: string }): Promise<SignalsResult> {
  const q = new URLSearchParams();
  if (params?.asset_ref_id) q.set("asset_ref_id", params.asset_ref_id);
  if (params?.signal_type) q.set("signal_type", params.signal_type);
  const qs = q.toString();
  return api.get<SignalsResult>(`/api/v1/ml-pipeline/signals${qs ? `?${qs}` : ""}`);
}

export function runInference(body: {
  model_type: string;
  assets: Array<Record<string, unknown>>;
}): Promise<InferenceResult> {
  return api.post<InferenceResult>("/api/v1/ml-pipeline/inference", body);
}

export function checkDrift(modelId: string, actual: number[]): Promise<DriftResult> {
  return api.post<DriftResult>(`/api/v1/ml-pipeline/models/${modelId}/drift-check`, { actual });
}
