/**
 * Threat Intelligence API client — M18 live-telemetry expansion pass.
 *
 * organization_id is never sent by the client — the backend derives it
 * from the caller's verified token. Provider config `credential_ref`
 * is always an env-var NAME configured on the server, never a secret
 * value — this client never accepts or sends a raw credential.
 */
import { api } from "@/lib/api";

export interface ProviderConfig {
  provider_name: string;
  enabled: boolean;
  allowed_indicator_types: string[];
  credential_ref: string | null;
  config: Record<string, string>;
  is_optional_disclaimer_required: boolean;
  updated_at: string;
}

export interface ProviderHealth {
  provider_name: string;
  configured: boolean;
  enabled: boolean;
  status: string;
  last_success_at: string | null;
  last_error_category: string | null;
  last_error_at: string | null;
  circuit_state: string;
}

export interface Indicator {
  id: string;
  indicator: string;
  indicator_type: string;
  first_seen_at: string;
  last_seen_at: string;
}

export interface Enrichment {
  provider_name: string;
  kind: string;
  success: boolean;
  error_category: string | null;
  data: Record<string, unknown>;
  fetched_at: string;
  expires_at: string;
}

export interface EnrichIpResult {
  egress_decision: string;
  reputation: Record<string, unknown>[];
  geolocation: Record<string, unknown> | null;
  asn: Record<string, unknown> | null;
  provider_errors: Record<string, unknown>[];
}

export interface CorrelationRunResult {
  indicators_checked: number;
  matches_found: number;
  provider_errors: Record<string, unknown>[];
}

export const PROVIDER_LABELS: Record<string, string> = {
  abuseipdb: "AbuseIPDB",
  alienvault_otx: "AlienVault OTX",
  spamhaus_drop: "Spamhaus DROP/EDROP",
  rdap: "RDAP (ASN/Network Owner)",
  maxmind_geolite_local: "MaxMind GeoLite2 (local)",
  ipinfo_lite: "IPinfo Lite (geo fallback)",
  greynoise_community: "GreyNoise Community",
  abusech: "abuse.ch (URLhaus/ThreatFox)",
};

export function listProviders(): Promise<ProviderConfig[]> {
  return api.get<ProviderConfig[]>("/api/v1/threat-intel/providers");
}

export function configureProvider(
  providerName: string,
  body: {
    enabled: boolean;
    allowed_indicator_types: string[];
    credential_ref?: string | null;
    config?: Record<string, string> | null;
  },
): Promise<ProviderConfig> {
  return api.put<ProviderConfig>(
    `/api/v1/threat-intel/providers/${encodeURIComponent(providerName)}`,
    body,
  );
}

export function getProviderHealth(): Promise<ProviderHealth[]> {
  return api.get<ProviderHealth[]>("/api/v1/threat-intel/health");
}

export function listIndicators(limit = 50, offset = 0): Promise<Indicator[]> {
  return api.get<Indicator[]>(`/api/v1/threat-intel/indicators?limit=${limit}&offset=${offset}`);
}

export function getIndicatorEnrichments(indicatorId: string): Promise<Enrichment[]> {
  return api.get<Enrichment[]>(
    `/api/v1/threat-intel/indicators/${encodeURIComponent(indicatorId)}/enrichments`,
  );
}

export function enrichIp(ip: string): Promise<EnrichIpResult> {
  return api.post<EnrichIpResult>(`/api/v1/threat-intel/enrich/ip/${encodeURIComponent(ip)}`);
}

export function runCorrelation(limit = 50): Promise<CorrelationRunResult> {
  return api.post<CorrelationRunResult>(`/api/v1/threat-intel/correlate?limit=${limit}`);
}
