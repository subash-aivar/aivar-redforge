/**
 * IOC Intelligence API client (M51.2 Phase A6).
 *
 * tenant_id is NEVER sent by this client — the backend derives tenant
 * scope from the caller's verified token for every `/observations/tenant`
 * and `/{ioc_id}/...` canonical-route call. Global routes
 * (`/observations/global`) require the caller to hold real platform
 * authority; this client sends no role/permission header of any kind —
 * the backend is the sole source of truth for what a given caller may do.
 *
 * No backend business rule (lifecycle/epistemic transition legality,
 * provenance validation, deduplication) is re-implemented here — every
 * mutation is submitted as-is and the backend's own validation errors
 * are surfaced honestly via `ApiError`.
 */
import { api } from "@/lib/api";

export interface SourceAttribution {
  source_system: string;
  external_id: string;
  content_hash: string | null;
  observed_at: string;
  weight_applied: number;
  confidence: string;
}

export interface EvidenceCitation {
  value: string;
}

export interface IocSummary {
  ioc_id: string;
  tenant_id: string | null;
  ioc_type: string;
  canonical_key: string;
  lifecycle: string;
  epistemic_state: string;
  created_at: string;
  updated_at: string;
  valid_until: string | null;
  source_count: number;
  evidence_count: number;
}

export interface IocDetail extends IocSummary {
  valid_from: string;
  valid_until: string | null;
  source_attributions: SourceAttribution[];
  evidence_citations: EvidenceCitation[];
}

export interface PaginatedIocList {
  items: IocSummary[];
  // `count` = this page's size (== items.length); `total` = the real
  // count across the ENTIRE filtered dataset, computed server-side —
  // use `total` for "N results" / pagination-bounds UI, never `count`.
  count: number;
  total: number;
  limit: number;
  offset: number;
}

export interface IocListFilters {
  lifecycle?: string;
  epistemic_state?: string;
  ioc_type?: string;
  search?: string;
  confidence?: string;
  source_system?: string;
  validity?: "valid" | "lapsed";
  sort_by?: IocSortField;
  sort_dir?: "asc" | "desc";
  limit?: number;
  offset?: number;
}

export const IOC_SORT_FIELD_VALUES = [
  "created_at",
  "updated_at",
  "valid_until",
  "ioc_type",
  "lifecycle",
  "epistemic_state",
] as const;
export type IocSortField = (typeof IOC_SORT_FIELD_VALUES)[number];

export const IOC_VALIDITY_VALUES = ["valid", "lapsed"] as const;

export interface SourceAttributionInput {
  source_system: string;
  external_id: string;
  observed_at: string;
  weight_applied: number;
  confidence: string;
  content_hash?: string | null;
}

export interface EvidenceCitationInput {
  entity_type: "SecurityCondition" | "InvestigationCase";
  entity_id: string;
}

export interface ObserveIocInput {
  ioc_type: string;
  raw_value: string;
  source_attributions?: SourceAttributionInput[];
  evidence_citations?: EvidenceCitationInput[];
}

function serializeFilters(filters: IocListFilters): string {
  const params = new URLSearchParams();
  if (filters.lifecycle) params.set("lifecycle", filters.lifecycle);
  if (filters.epistemic_state) params.set("epistemic_state", filters.epistemic_state);
  if (filters.ioc_type) params.set("ioc_type", filters.ioc_type);
  if (filters.search) params.set("search", filters.search);
  if (filters.confidence) params.set("confidence", filters.confidence);
  if (filters.source_system) params.set("source_system", filters.source_system);
  if (filters.validity) params.set("validity", filters.validity);
  if (filters.sort_by) params.set("sort_by", filters.sort_by);
  if (filters.sort_dir) params.set("sort_dir", filters.sort_dir);
  params.set("limit", String(filters.limit ?? 50));
  params.set("offset", String(filters.offset ?? 0));
  return params.toString();
}

export function listTenantIocs(filters: IocListFilters = {}): Promise<PaginatedIocList> {
  return api.get<PaginatedIocList>(`/api/v1/iocs?${serializeFilters(filters)}`);
}

export function listGlobalIocs(filters: IocListFilters = {}): Promise<PaginatedIocList> {
  return api.get<PaginatedIocList>(`/api/v1/iocs/global?${serializeFilters(filters)}`);
}

export function getIoc(iocId: string): Promise<IocDetail> {
  return api.get<IocDetail>(`/api/v1/iocs/${encodeURIComponent(iocId)}`);
}

export function observeTenantIoc(body: ObserveIocInput): Promise<IocDetail> {
  return api.post<IocDetail>("/api/v1/iocs/observations/tenant", body);
}

export function observeGlobalIoc(body: ObserveIocInput): Promise<IocDetail> {
  return api.post<IocDetail>("/api/v1/iocs/observations/global", body);
}

export function addSourceAttribution(
  iocId: string,
  attribution: SourceAttributionInput,
): Promise<IocDetail> {
  return api.post<IocDetail>(`/api/v1/iocs/${encodeURIComponent(iocId)}/sources`, {
    attribution,
  });
}

export function addEvidenceCitation(
  iocId: string,
  citation: EvidenceCitationInput,
): Promise<IocDetail> {
  return api.post<IocDetail>(`/api/v1/iocs/${encodeURIComponent(iocId)}/evidence`, {
    citation,
  });
}

export function transitionLifecycle(iocId: string, targetLifecycle: string): Promise<IocDetail> {
  return api.patch<IocDetail>(`/api/v1/iocs/${encodeURIComponent(iocId)}/lifecycle`, {
    target_lifecycle: targetLifecycle,
  });
}

export function transitionEpistemicState(iocId: string, targetState: string): Promise<IocDetail> {
  return api.patch<IocDetail>(`/api/v1/iocs/${encodeURIComponent(iocId)}/epistemic-state`, {
    target_state: targetState,
  });
}

export function disputeIoc(iocId: string): Promise<IocDetail> {
  return api.post<IocDetail>(`/api/v1/iocs/${encodeURIComponent(iocId)}/dispute`);
}

export function refuteIoc(iocId: string, reason: string): Promise<IocDetail> {
  return api.post<IocDetail>(`/api/v1/iocs/${encodeURIComponent(iocId)}/refute`, { reason });
}

export function refreshIoc(iocId: string): Promise<IocDetail> {
  return api.post<IocDetail>(`/api/v1/iocs/${encodeURIComponent(iocId)}/refresh`);
}

export function supersedeIoc(iocId: string): Promise<IocDetail> {
  return api.post<IocDetail>(`/api/v1/iocs/${encodeURIComponent(iocId)}/supersede`);
}

export function revokeIoc(iocId: string): Promise<IocDetail> {
  return api.post<IocDetail>(`/api/v1/iocs/${encodeURIComponent(iocId)}/revoke`);
}

export const IOC_LIFECYCLE_VALUES = ["active", "superseded", "expired", "revoked"] as const;
export const IOC_EPISTEMIC_VALUES = [
  "observation",
  "evidence",
  "hypothesis",
  "corroborated",
  "validated",
  "disputed",
  "refuted",
  "historical",
  "retired",
] as const;
export const IOC_TYPE_VALUES = ["ip", "domain", "url", "hash"] as const;

/**
 * Closed provider vocabulary, mirrored from the certified backend's
 * `redforge.shared.ioc_vocabulary.ProviderName` enum (same mirroring
 * pattern already used above for lifecycle/epistemic/type values). Not
 * a new API surface — the backend has no "list providers" endpoint, so
 * this is the frontend's honest reflection of the same closed set the
 * backend already enforces; submitting anything outside it always
 * fails backend validation regardless of what this list contains.
 */
export const IOC_PROVIDER_VALUES = [
  "abuseipdb",
  "alienvault_otx",
  "spamhaus_drop",
  "rdap",
  "maxmind_geolite_local",
  "ipinfo_lite",
  "greynoise_community",
  "abusech",
  "redforge_internal_observation",
] as const;

export const IOC_PROVIDER_LABELS: Record<string, string> = {
  abuseipdb: "AbuseIPDB",
  alienvault_otx: "AlienVault OTX",
  spamhaus_drop: "Spamhaus DROP",
  rdap: "RDAP",
  maxmind_geolite_local: "MaxMind GeoLite (local)",
  ipinfo_lite: "IPinfo Lite",
  greynoise_community: "GreyNoise Community",
  abusech: "abuse.ch",
  redforge_internal_observation: "Internal (RedForge Observation)",
};

export const IOC_PROVIDER_REFERENCE_PLACEHOLDER: Record<string, string> = {
  abuseipdb: "e.g. AIPDB-88213",
  alienvault_otx: "e.g. OTX-123456",
  spamhaus_drop: "e.g. DROP-19.2.3.0/24",
  rdap: "e.g. RDAP-198.51.100.0",
  maxmind_geolite_local: "e.g. GEOLITE-198.51.100.0",
  ipinfo_lite: "e.g. IPINFO-198.51.100.0",
  greynoise_community: "e.g. GNC-198.51.100.42",
  abusech: "e.g. ABUSECH-9981",
  redforge_internal_observation: "e.g. analyst-case-4471",
};

export const IOC_CONFIDENCE_VALUES = ["low", "medium", "high", "very_high"] as const;
export const IOC_CONFIDENCE_LABELS: Record<string, string> = {
  low: "Low",
  medium: "Medium",
  high: "High",
  very_high: "Very High",
};
