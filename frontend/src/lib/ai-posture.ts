import { api } from "@/lib/api";

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
  return api.get<AIAssetInventoryDashboard>("/api/v1/ai-posture/dashboards/inventory");
}

export function getShadowDiscoveryReport(): Promise<ShadowAIDiscoveryReport> {
  return api.get<ShadowAIDiscoveryReport>("/api/v1/ai-posture/reports/shadow-ai-discovery");
}

export function getAsset(assetId: string): Promise<AISystemAsset> {
  return api.get<AISystemAsset>(`/api/v1/ai-posture/assets/${assetId}`);
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
