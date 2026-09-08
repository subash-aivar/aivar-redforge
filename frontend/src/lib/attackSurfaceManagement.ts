/**
 * Attack Surface Management API client — M49D.
 *
 * Same situation as `riskEngine.ts` was: no frontend consumer existed
 * for this backend context (`attack_surface_management`, distinct
 * from the generic `assets` inventory context AND from the separate
 * `securityCorrelations` "Attack Surface" exposure-concentration page
 * — three real, separately-owned bounded contexts, not duplication)
 * until the SOC dashboard's KPI wall/treemap started using the
 * list-only shape below. This file now exposes the full real asset
 * shape (`AssetResponse` in `attack_surface_management/api/schemas
 * /attack_surface_schemas.py` — ports, certificates, DNS records,
 * technology fingerprints all already come back on every list item,
 * confirmed by reading the schema, so no extra per-asset detail call
 * is needed for a drill-down drawer) to back a real operational
 * landing page.
 */
import { api } from "@/lib/api";

export interface AssetOwnership {
  owning_team: string | null;
  contact: string | null;
}

export interface OpenPort {
  port_id: string;
  port_number: number;
  protocol: string;
  state: string;
  detected_at: string;
  is_high_risk: boolean;
  service_name: string | null;
  service_version: string | null;
}

export interface Certificate {
  certificate_id: string;
  common_name: string;
  issuer: string;
  serial_number: string;
  not_before: string;
  not_after: string;
  status: string;
}

export interface DnsRecord {
  record_id: string;
  record_type: string;
  name: string;
  value: string;
  ttl_seconds: number;
  detected_at: string;
}

export interface TechnologyFingerprint {
  name: string;
  version: string | null;
  confidence: number;
}

export interface Asset {
  asset_id: string;
  tenant_id: string;
  asset_type: string;
  primary_identifier: string;
  discovery_source: string;
  classification: string;
  criticality: string;
  exposure_state: string;
  lifecycle_state: string;
  created_at: string;
  updated_at: string;
  domain_name: string | null;
  subdomain: string | null;
  ip_address: string | null;
  ownership: AssetOwnership | null;
  ports: OpenPort[];
  certificates: Certificate[];
  dns_records: DnsRecord[];
  fingerprints: TechnologyFingerprint[];
}

export interface ListAssetsResponse {
  items: Asset[];
  count: number;
}

export function listAssets(
  params: { exposure_state?: string; criticality?: string; limit?: number } = {}
): Promise<ListAssetsResponse> {
  const query = new URLSearchParams();
  if (params.exposure_state) query.set("exposure_state", params.exposure_state);
  if (params.criticality) query.set("criticality", params.criticality);
  if (params.limit) query.set("limit", String(params.limit));
  const qs = query.toString();
  return api.get<ListAssetsResponse>(`/api/v1/attack-surface-management/assets${qs ? `?${qs}` : ""}`);
}

/** Every value of the backend's `ExposureState` enum (attack_surface_management/domain/value_objects/enums.py). */
export const EXPOSURE_STATES = ["unknown", "not_exposed", "internet_facing", "exposed_high_risk"] as const;
export type ExposureState = (typeof EXPOSURE_STATES)[number];

/**
 * Coverage-by-exposure-state counts for the landing page. Same pattern
 * as `riskEngine.getRiskProfileCoverage` — no count-by-state aggregate
 * endpoint exists, so this issues one filtered request per state (4
 * total) and reads each response's real `count`.
 */
export async function getExposureStateCoverage(): Promise<Record<ExposureState, number>> {
  const results = await Promise.all(
    EXPOSURE_STATES.map((exposure_state) => listAssets({ exposure_state, limit: 1 }))
  );
  const coverage = {} as Record<ExposureState, number>;
  EXPOSURE_STATES.forEach((state, i) => {
    coverage[state] = results[i].count;
  });
  return coverage;
}
