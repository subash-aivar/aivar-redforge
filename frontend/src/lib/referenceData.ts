/**
 * Threat Intelligence Reference Data API client — M22 Phase 1.
 *
 * All endpoints require platform permissions (PlatformPermission).
 * These are global (not tenant-scoped) catalog tables: ATT&CK tactics,
 * techniques, relationships, and CVE vulnerabilities.
 */
import { api } from "@/lib/api";

// ── Response types ─────────────────────────────────────────────────────────

export interface AttackTactic {
  tactic_id: string;
  name: string;
  shortname: string;
  description: string;
  stix_id: string;
  url: string | null;
  created_at: string;
  updated_at: string;
}

export interface AttackTechnique {
  technique_id: string;
  name: string;
  description: string;
  stix_id: string;
  is_sub_technique: boolean;
  parent_technique_id: string | null;
  tactic_ids: string[];
  platforms: string[];
  data_sources: string[];
  is_deprecated: boolean;
  is_revoked: boolean;
  framework_version: string | null;
  created_at: string | null;
  updated_at: string | null;
}

export interface TechniqueRelationship {
  stix_id: string;
  relationship_type: string;
  source_ref: string;
  target_ref: string;
  source_technique_id: string | null;
  target_technique_id: string | null;
  description: string;
  created_at: string;
  updated_at: string;
}

export interface CvssScore {
  version: string;
  base_score: number;
  vector: string;
  severity: string;
}

export interface EpssScore {
  probability: number;
  percentile: number;
  model_date: string;
}

export interface Vulnerability {
  cve_id: string;
  description: string;
  cvss_v3: CvssScore | null;
  cvss_v2_score: number | null;
  epss: EpssScore | null;
  is_kev: boolean;
  kev_date_added: string | null;
  kev_due_date: string | null;
  kev_vulnerability_name: string | null;
  kev_short_description: string | null;
  kev_required_action: string | null;
  kev_known_ransomware_use: boolean;
  published_at: string | null;
  last_modified_at: string | null;
  source_last_synced_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface IngestionRecord {
  id: string;
  source_system: string;
  scope: string;
  organization_id: string | null;
  object_type: string;
  external_id: string;
  content_hash: string;
  ingested_at: string;
  batch_id: string | null;
}

// ── API functions ──────────────────────────────────────────────────────────

export function listTactics(
  params: { limit?: number; offset?: number } = {},
): Promise<AttackTactic[]> {
  const q = new URLSearchParams();
  if (params.limit != null) q.set("limit", String(params.limit));
  if (params.offset != null) q.set("offset", String(params.offset));
  const qs = q.toString();
  return api.get<AttackTactic[]>(
    `/api/v1/threat-intel/reference-data/tactics${qs ? `?${qs}` : ""}`,
  );
}

export function getTactic(tacticId: string): Promise<AttackTactic> {
  return api.get<AttackTactic>(
    `/api/v1/threat-intel/reference-data/tactics/${encodeURIComponent(tacticId)}`,
  );
}

/** Requires either tactic_id or search — the backend returns 422 if neither supplied. */
export function listTechniquesByTactic(
  tacticId: string,
  params: { limit?: number; offset?: number } = {},
): Promise<AttackTechnique[]> {
  const q = new URLSearchParams({ tactic_id: tacticId });
  if (params.limit != null) q.set("limit", String(params.limit));
  if (params.offset != null) q.set("offset", String(params.offset));
  return api.get<AttackTechnique[]>(
    `/api/v1/threat-intel/reference-data/techniques?${q.toString()}`,
  );
}

export function searchTechniques(
  search: string,
  params: { limit?: number; offset?: number } = {},
): Promise<AttackTechnique[]> {
  const q = new URLSearchParams({ search });
  if (params.limit != null) q.set("limit", String(params.limit));
  if (params.offset != null) q.set("offset", String(params.offset));
  return api.get<AttackTechnique[]>(
    `/api/v1/threat-intel/reference-data/techniques?${q.toString()}`,
  );
}

export function getTechnique(techniqueId: string): Promise<AttackTechnique> {
  return api.get<AttackTechnique>(
    `/api/v1/threat-intel/reference-data/techniques/${encodeURIComponent(techniqueId)}`,
  );
}

export function listSubTechniques(techniqueId: string): Promise<AttackTechnique[]> {
  return api.get<AttackTechnique[]>(
    `/api/v1/threat-intel/reference-data/techniques/${encodeURIComponent(techniqueId)}/sub-techniques`,
  );
}

export function listTechniqueRelationships(
  techniqueId: string,
  relationshipType?: string,
): Promise<TechniqueRelationship[]> {
  const q = new URLSearchParams();
  if (relationshipType) q.set("relationship_type", relationshipType);
  const qs = q.toString();
  return api.get<TechniqueRelationship[]>(
    `/api/v1/threat-intel/reference-data/techniques/${encodeURIComponent(techniqueId)}/relationships${qs ? `?${qs}` : ""}`,
  );
}

/** Requires kev_only=true or min_epss_probability — backend returns 422 if neither. */
export function listKevVulnerabilities(
  params: { limit?: number; offset?: number } = {},
): Promise<Vulnerability[]> {
  const q = new URLSearchParams({ kev_only: "true" });
  if (params.limit != null) q.set("limit", String(params.limit));
  if (params.offset != null) q.set("offset", String(params.offset));
  return api.get<Vulnerability[]>(
    `/api/v1/threat-intel/reference-data/vulnerabilities?${q.toString()}`,
  );
}

export function listHighEpssVulnerabilities(
  minProbability: number,
  params: { limit?: number; offset?: number } = {},
): Promise<Vulnerability[]> {
  const q = new URLSearchParams({ min_epss_probability: String(minProbability) });
  if (params.limit != null) q.set("limit", String(params.limit));
  if (params.offset != null) q.set("offset", String(params.offset));
  return api.get<Vulnerability[]>(
    `/api/v1/threat-intel/reference-data/vulnerabilities?${q.toString()}`,
  );
}

export function getVulnerability(cveId: string): Promise<Vulnerability> {
  return api.get<Vulnerability>(
    `/api/v1/threat-intel/reference-data/vulnerabilities/${encodeURIComponent(cveId)}`,
  );
}

export function listIngestions(
  params: { source_system?: string; limit?: number; offset?: number } = {},
): Promise<IngestionRecord[]> {
  const q = new URLSearchParams();
  if (params.source_system) q.set("source_system", params.source_system);
  if (params.limit != null) q.set("limit", String(params.limit));
  if (params.offset != null) q.set("offset", String(params.offset));
  const qs = q.toString();
  return api.get<IngestionRecord[]>(
    `/api/v1/threat-intel/reference-data/ingestions${qs ? `?${qs}` : ""}`,
  );
}

// ── Display helpers ────────────────────────────────────────────────────────

export function cvssColor(score: number): string {
  if (score >= 9) return "border-red-800 bg-red-950/60 text-red-300";
  if (score >= 7) return "border-orange-800 bg-orange-950/50 text-orange-300";
  if (score >= 4) return "border-yellow-800 bg-yellow-950/50 text-yellow-300";
  return "border-gray-700 bg-gray-800 text-gray-300";
}

export function cvssLabel(score: number): string {
  if (score >= 9) return "Critical";
  if (score >= 7) return "High";
  if (score >= 4) return "Medium";
  if (score > 0) return "Low";
  return "None";
}
