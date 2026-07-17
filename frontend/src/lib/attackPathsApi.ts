/**
 * Attack Path Engine API client — M22 Phase 5.
 *
 * All endpoints require platform permissions (PlatformPermission).
 * The real backend routes live at /api/v1/attack-paths (NOT under
 * /api/v1/threat-intel/attack-paths which was a stub path).
 * organization_id is a required query/body param — attack paths are
 * computed per-org but administered at the platform level.
 */
import { api } from "@/lib/api";

// ── Response types ─────────────────────────────────────────────────────────

export interface AttackStep {
  sequence: number;
  entity_id: string;
  canonical_key: string;
  step_type: string;
  confidence: string;
  technique_id: string | null;
  evidence_refs: string[];
  relationship_type: string | null;
  kill_chain_phase: string | null;
  inferred_from_step: number | null;
  exposure_score: number;
}

export interface AttackPath {
  id: string;
  organization_id: string;
  root_entity_id: string;
  root_canonical_key: string;
  terminal_entity_id: string | null;
  path_confidence: string;
  technique_coverage: string[];
  attributed_actors: string[];
  step_count: number;
  evidence_count: number;
  max_exposure_score: number;
  status: string;
  steps: AttackStep[] | null;
  alternate_path_count: number | null;
  investigation_id?: string | null;
}

// ── API functions ──────────────────────────────────────────────────────────

export function computeAttackPath(body: {
  organization_id: string;
  seed_indicator_id: string;
}): Promise<AttackPath> {
  return api.post<AttackPath>("/api/v1/attack-paths/compute", body);
}

export function listAttackPaths(params: {
  organization_id: string;
  status?: string;
  root_technique_id?: string;
  confidence_floor?: string;
  limit?: number;
  offset?: number;
}): Promise<AttackPath[]> {
  const q = new URLSearchParams({ organization_id: params.organization_id });
  if (params.status) q.set("status", params.status);
  if (params.root_technique_id) q.set("root_technique_id", params.root_technique_id);
  if (params.confidence_floor) q.set("confidence_floor", params.confidence_floor);
  if (params.limit != null) q.set("limit", String(params.limit));
  if (params.offset != null) q.set("offset", String(params.offset));
  return api.get<AttackPath[]>(`/api/v1/attack-paths?${q.toString()}`);
}

export function getAttackPath(
  pathId: string,
  organizationId: string,
): Promise<AttackPath> {
  return api.get<AttackPath>(
    `/api/v1/attack-paths/${encodeURIComponent(pathId)}?organization_id=${encodeURIComponent(organizationId)}`,
  );
}

export function containAttackPath(
  pathId: string,
  organizationId: string,
): Promise<AttackPath> {
  return api.post<AttackPath>(
    `/api/v1/attack-paths/${encodeURIComponent(pathId)}/contain?organization_id=${encodeURIComponent(organizationId)}`,
  );
}

export function archiveAttackPath(
  pathId: string,
  organizationId: string,
): Promise<AttackPath> {
  return api.post<AttackPath>(
    `/api/v1/attack-paths/${encodeURIComponent(pathId)}/archive?organization_id=${encodeURIComponent(organizationId)}`,
  );
}

// ── Display helpers ────────────────────────────────────────────────────────

export function pathConfidenceColor(confidence: string): string {
  switch (confidence.toLowerCase()) {
    case "high": return "border-emerald-800 bg-emerald-950/50 text-emerald-300";
    case "medium": return "border-yellow-800 bg-yellow-950/50 text-yellow-300";
    case "low": return "border-orange-800 bg-orange-950/50 text-orange-300";
    case "very_low": return "border-red-800 bg-red-950/50 text-red-300";
    default: return "border-gray-700 bg-gray-800 text-gray-400";
  }
}

export function pathStatusColor(status: string): string {
  switch (status.toLowerCase()) {
    case "active": return "border-red-800 bg-red-950/60 text-red-300";
    case "contained": return "border-yellow-800 bg-yellow-950/50 text-yellow-300";
    case "historical": return "border-gray-700 bg-gray-800 text-gray-400";
    default: return "border-gray-700 bg-gray-800 text-gray-400";
  }
}

export function stepConfidenceColor(confidence: string): string {
  switch (confidence.toLowerCase()) {
    case "high": return "#34d399";
    case "medium": return "#fbbf24";
    case "low": return "#fb923c";
    case "very_low": return "#f87171";
    default: return "#6b7280";
  }
}

/** Canonical ATT&CK kill-chain phase ordering for swimlane layout. */
export const KILL_CHAIN_ORDER: Record<string, number> = {
  reconnaissance: 0,
  "resource-development": 1,
  "initial-access": 2,
  execution: 3,
  persistence: 4,
  "privilege-escalation": 5,
  "defense-evasion": 6,
  "credential-access": 7,
  discovery: 8,
  "lateral-movement": 9,
  collection: 10,
  "command-and-control": 11,
  exfiltration: 12,
  impact: 13,
};

export function phaseLabel(phase: string | null): string {
  if (!phase) return "Unknown";
  return phase
    .split("-")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}
