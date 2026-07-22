import { api } from "@/lib/api";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface RemediationCandidate {
  remediation_id: string;
  affected_asset_refs: string[];
  estimated_amplifier_removals: string[];
  estimated_base_reduction: number;
}

export interface PlanStepDTO {
  remediation_id: string;
  marginal_delta: number;
  affected_asset_refs: string[];
  rank: number;
}

export interface ExposureReductionPlanDTO {
  plan_id: string;
  tenant_id: string;
  status: string;
  generated_at: string;
  committed_at: string | null;
  committed_by: string | null;
  is_stale: boolean;
  projected_exposure_reduction: number;
  estimated_business_impact: number;
  algorithm: string;
  top_k: number;
  sample_size: number;
  approximation_mode: string;
  simulation_seed: number;
  score_input_version: number;
  plan_steps: PlanStepDTO[];
  metadata: Record<string, unknown>;
}

// ─── API ─────────────────────────────────────────────────────────────────────

export function generatePlan(body: {
  candidate_remediations: RemediationCandidate[];
  plan_budget?: number;
  top_k?: number;
  sample_size?: number;
  current_exposure_scores?: Record<string, number>;
  score_input_version?: number;
}): Promise<ExposureReductionPlanDTO> {
  return api.post<ExposureReductionPlanDTO>("/api/v1/remediation-impact/plans", body);
}

export function commitPlan(planId: string, committedBy: string): Promise<ExposureReductionPlanDTO> {
  return api.post<ExposureReductionPlanDTO>(`/api/v1/remediation-impact/plans/${planId}/commit`, {
    committed_by: committedBy,
  });
}

export function getPlan(planId: string): Promise<ExposureReductionPlanDTO> {
  return api.get<ExposureReductionPlanDTO>(`/api/v1/remediation-impact/plans/${planId}`);
}

export function listPlans(status?: string): Promise<ExposureReductionPlanDTO[]> {
  const q = status ? `?status=${encodeURIComponent(status)}` : "";
  return api.get<ExposureReductionPlanDTO[]>(`/api/v1/remediation-impact/plans${q}`);
}
