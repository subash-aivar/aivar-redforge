import { api, ApiError } from "@/lib/api";

export interface AIInventoryAssetSummary {
  asset_id: string;
  ai_system_kind: string;
  lifecycle_state: string;
}

export interface AIAssetInventoryDashboard {
  tenant_id: string;
  assets: AIInventoryAssetSummary[];
  last_scan_at: string | null;
  configured_discovery_sources: string[];
  coverage_scope: string;
  empty?: boolean;
}

export interface ShadowAlertSummary {
  alert_id: string;
  fingerprint_hash: string;
  discovery_source: string;
}

export interface ShadowAIDiscoveryReport {
  tenant_id: string;
  alerts: ShadowAlertSummary[];
  partial_scans: Record<string, unknown>[];
  empty?: boolean;
}

export interface AISystemAsset {
  asset_id: string;
  tenant_id: string;
  asset_ref_id: string;
  lifecycle_state: string;
  registration_status: string;
  ai_system_kind: string | null;
  owner_id: string | null;
  threat_profile_id: string | null;
  risk_score_snapshot_id: string | null;
  data_sensitivity: string;
}

export function getInventoryDashboard(): Promise<AIAssetInventoryDashboard> {
  return getOrEmpty<AIAssetInventoryDashboard>("/api/v1/ai-posture/dashboards/inventory", {
    tenant_id: "",
    assets: [],
    last_scan_at: null,
    configured_discovery_sources: [],
    coverage_scope: "",
  });
}

export function getShadowDiscoveryReport(): Promise<ShadowAIDiscoveryReport> {
  return getOrEmpty<ShadowAIDiscoveryReport>("/api/v1/ai-posture/reports/shadow-ai-discovery", {
    tenant_id: "",
    alerts: [],
    partial_scans: [],
  });
}

export function getAsset(assetId: string): Promise<AISystemAsset> {
  return api.get<AISystemAsset>(`/api/v1/ai-posture/assets/${assetId}`);
}

// ── Risk register, supply chain, and agent deviation reports ────────────────
//
// Real read-model projections (see `ai_posture/application/projections
// /read_models.py` + `projection_service.py`'s event handlers, which is
// where every field name below was confirmed) — previously unconsumed
// by any frontend page. Each raises a 404 from the backend
// (`ApplicationNotFoundError`) when no data has been computed for the
// tenant yet — treated here as an honest empty state (`{ empty: true }`),
// never as an error to alarm the operator with.

export interface RiskRegisterEntry {
  asset_id: string;
  composite_score: number;
  score_input_version: string;
  computed_at: string;
  is_stale: boolean;
}

export interface AIRiskRegister {
  tenant_id: string;
  entries: RiskRegisterEntry[];
  empty?: boolean;
}

export interface SupplyChainModelRow {
  asset_id: string;
  provenance_id: string;
  integrity_status: string;
  verification_method: string;
  tier_label: string;
  trust_delegation_note: string;
}

export interface AISupplyChainIntegrityReport {
  tenant_id: string;
  models: SupplyChainModelRow[];
  empty?: boolean;
}

export interface AgentDeviationRow {
  deviation_id: string;
  asset_id: string;
  deviation_type: string;
  severity: string;
  review_state: string;
}

export interface AIAgentDeviationReport {
  tenant_id: string;
  deviations: AgentDeviationRow[];
  empty?: boolean;
}

async function getOrEmpty<T extends { empty?: boolean }>(
  path: string,
  emptyShape: T
): Promise<T> {
  try {
    return await api.get<T>(path);
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) return { ...emptyShape, empty: true };
    throw e;
  }
}

export function getRiskRegister(): Promise<AIRiskRegister> {
  return getOrEmpty<AIRiskRegister>("/api/v1/ai-posture/dashboards/risk-register", {
    tenant_id: "",
    entries: [],
  });
}

export function getSupplyChainIntegrity(): Promise<AISupplyChainIntegrityReport> {
  return getOrEmpty<AISupplyChainIntegrityReport>("/api/v1/ai-posture/reports/supply-chain-integrity", {
    tenant_id: "",
    models: [],
  });
}

export function getAgentDeviations(): Promise<AIAgentDeviationReport> {
  return getOrEmpty<AIAgentDeviationReport>("/api/v1/ai-posture/reports/agent-deviations", {
    tenant_id: "",
    deviations: [],
  });
}

export function triageAlert(
  alertId: string,
  triagedBy: string,
  notes = ""
): Promise<unknown> {
  return api.post(`/api/v1/ai-posture/shadow-alerts/${alertId}/triage`, {
    triaged_by: triagedBy,
    notes,
  });
}

export function lifecycleTone(
  state: string
): "critical" | "high" | "warning" | "ok" | "neutral" {
  switch (state.toLowerCase()) {
    case "registered":
    case "approved":
      return "ok";
    case "shadow":
    case "unapproved":
      return "critical";
    case "decommissioned":
      return "neutral";
    default:
      return "warning";
  }
}
