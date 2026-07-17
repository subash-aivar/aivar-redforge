/**
 * Threat Fusion API client — M22 Phase 4.
 *
 * All endpoints require platform permissions (PlatformPermission).
 * Covers fused indicator management, fusion weight administration,
 * and manual fusion execution.
 */
import { api } from "@/lib/api";

// ── Response types ─────────────────────────────────────────────────────────

export interface FusedIndicator {
  id: string;
  canonical_key: string;
  indicator_type: string;
  display_name: string;
  lifecycle: string;
  confidence: string | null;
  risk_state: string;
  winner_source_system: string | null;
  source_count: number;
  metadata: Record<string, unknown>;
  valid_from: string;
  valid_until: string | null;
}

export interface FusionRunResult {
  indicators_created: number;
  indicators_updated: number;
  relationships_upserted: number;
  stub_indicators_created: number;
  no_evidence_count: number;
}

// ── API functions ──────────────────────────────────────────────────────────

export function runFusion(): Promise<FusionRunResult> {
  return api.post<FusionRunResult>("/api/v1/threat-intel/fusion/run");
}

export function listFusionWeights(): Promise<Record<string, number>> {
  return api.get<Record<string, number>>("/api/v1/threat-intel/fusion/weights");
}

export function updateFusionWeight(
  sourceSystem: string,
  weight: number,
): Promise<Record<string, number>> {
  return api.put<Record<string, number>>("/api/v1/threat-intel/fusion/weights", {
    source_system: sourceSystem,
    weight,
  });
}

export function listFusedIndicators(params: {
  indicator_type: string;
  lifecycle?: string;
  limit?: number;
  offset?: number;
}): Promise<FusedIndicator[]> {
  const q = new URLSearchParams({ indicator_type: params.indicator_type });
  if (params.lifecycle) q.set("lifecycle", params.lifecycle);
  if (params.limit != null) q.set("limit", String(params.limit));
  if (params.offset != null) q.set("offset", String(params.offset));
  return api.get<FusedIndicator[]>(
    `/api/v1/threat-intel/fusion/indicators?${q.toString()}`,
  );
}

export function getFusedIndicator(indicatorId: string): Promise<FusedIndicator> {
  return api.get<FusedIndicator>(
    `/api/v1/threat-intel/fusion/indicators/${encodeURIComponent(indicatorId)}`,
  );
}

// ── Display helpers ────────────────────────────────────────────────────────

export function confidenceColor(confidence: string | null): string {
  if (!confidence) return "border-gray-700 bg-gray-800 text-gray-400";
  switch (confidence.toLowerCase()) {
    case "high": return "border-emerald-800 bg-emerald-950/50 text-emerald-300";
    case "medium": return "border-yellow-800 bg-yellow-950/50 text-yellow-300";
    case "low": return "border-orange-800 bg-orange-950/50 text-orange-300";
    case "very_low": return "border-red-800 bg-red-950/50 text-red-300";
    default: return "border-gray-700 bg-gray-800 text-gray-400";
  }
}

export function riskStateColor(riskState: string): string {
  switch (riskState.toLowerCase()) {
    case "critical": return "border-red-800 bg-red-950/60 text-red-300";
    case "high": return "border-orange-800 bg-orange-950/50 text-orange-300";
    case "medium": return "border-yellow-800 bg-yellow-950/50 text-yellow-300";
    case "low": return "border-blue-800 bg-blue-950/50 text-blue-300";
    case "no_evidence": return "border-gray-700 bg-gray-800 text-gray-500";
    default: return "border-gray-700 bg-gray-800 text-gray-400";
  }
}

export function lifecycleColor(lifecycle: string): string {
  switch (lifecycle.toLowerCase()) {
    case "active": return "border-emerald-800 bg-emerald-950/50 text-emerald-300";
    case "superseded": return "border-yellow-800 bg-yellow-950/50 text-yellow-300";
    case "expired": return "border-gray-700 bg-gray-800 text-gray-400";
    case "revoked": return "border-red-800 bg-red-950/50 text-red-300";
    default: return "border-gray-700 bg-gray-800 text-gray-400";
  }
}

export const INDICATOR_TYPE_LABELS: Record<string, string> = {
  technique: "ATT&CK Technique",
  tactic: "ATT&CK Tactic",
  vulnerability: "Vulnerability",
  software: "Software",
  campaign: "Campaign",
  group: "Threat Group",
  mitigation: "Mitigation",
};

export const INDICATOR_TYPES = [
  "technique",
  "tactic",
  "vulnerability",
  "software",
  "campaign",
  "group",
  "mitigation",
] as const;
