/**
 * AIVAR RedForge — Security Operations Command Center API client (M18).
 *
 * Typed wrappers over the /command-center/* and the M18 /network-security/*
 * read surfaces. Every call is tenant-scoped by the backend from the
 * bearer token; organization_id is never sent from the client.
 */

import { api } from "@/lib/api";

// ── Overview ────────────────────────────────────────────────────────────────

export interface PostureContribution {
  factor: string;
  count: number;
  weight: number;
  deduction: number;
}

export interface HighRiskAsset {
  asset_id: string;
  asset_name: string;
  asset_type: string;
  active_condition_count: number;
}

export interface CommandOverview {
  posture_score: number;
  posture_band: string;
  posture_formula_version: string;
  posture_total_deduction: number;
  posture_contributions: PostureContribution[];
  active_condition_count: number;
  active_conditions_by_severity: Record<string, number>;
  active_correlation_count: number;
  high_risk_assets: HighRiskAsset[];
  asset_inventory_by_type: Record<string, number>;
  total_assets: number;
  zone_counts: Record<string, number>;
  validation_run_counts: Record<string, number>;
}

export function getCommandOverview(): Promise<CommandOverview> {
  return api.get<CommandOverview>("/api/v1/command-center/overview");
}

// ── Behavior analytics (UEBA / HBA / NBA) ────────────────────────────────────

export interface BehaviorEvidence {
  source: string;
  source_id: string;
  occurred_at: string;
  detail: string;
}

export interface BehaviorSignal {
  domain: string;
  signal_type: string;
  severity: string;
  subject: string;
  summary: string;
  observed_window: string;
  evidence_count: number;
  evidence: BehaviorEvidence[];
}

export function getBehaviorSignals(
  period = "24h",
  domain?: string,
): Promise<BehaviorSignal[]> {
  const q = new URLSearchParams({ period });
  if (domain) q.set("domain", domain);
  return api.get<BehaviorSignal[]>(`/api/v1/command-center/behavior?${q.toString()}`);
}

// ── Integration boundaries (NOT CONFIGURED until wired) ──────────────────────

export interface IntegrationStatus {
  integration_type: string;
  provider_name: string | null;
  status: string;
  last_telemetry_at: string | null;
  detail: string;
}

export function listIntegrations(): Promise<IntegrationStatus[]> {
  return api.get<IntegrationStatus[]>("/api/v1/command-center/integrations");
}

export function registerIntegration(
  integrationType: string,
  providerName: string,
  config?: Record<string, string>,
): Promise<IntegrationStatus> {
  return api.put<IntegrationStatus>(
    `/api/v1/command-center/integrations/${encodeURIComponent(integrationType)}`,
    { provider_name: providerName, config: config ?? null },
  );
}

export function disableIntegration(integrationType: string): Promise<{ removed: boolean }> {
  return api.delete<{ removed: boolean }>(
    `/api/v1/command-center/integrations/${encodeURIComponent(integrationType)}`,
  );
}

// ── Network zones / DMZ ──────────────────────────────────────────────────────

export interface ZoneAssignment {
  asset_id: string;
  asset_name: string;
  asset_type: string;
  zone_type: string;
  note: string;
  assigned_by: string;
  updated_at: string;
}

export interface DmzAsset {
  asset_id: string;
  asset_name: string;
  asset_type: string;
  active_condition_count: number;
}

export interface ZoneOverview {
  counts_by_zone: Record<string, number>;
  dmz_assets: DmzAsset[];
}

export function getZoneOverview(): Promise<ZoneOverview> {
  return api.get<ZoneOverview>("/api/v1/command-center/zones/overview");
}

export function listZoneAssignments(zoneType?: string): Promise<ZoneAssignment[]> {
  const q = zoneType ? `?zone_type=${encodeURIComponent(zoneType)}` : "";
  return api.get<ZoneAssignment[]>(`/api/v1/command-center/zones${q}`);
}

export function assignZone(
  assetId: string,
  zoneType: string,
  note = "",
): Promise<ZoneAssignment> {
  return api.post<ZoneAssignment>("/api/v1/command-center/zones", {
    asset_id: assetId,
    zone_type: zoneType,
    note,
  });
}

export function unassignZone(assetId: string): Promise<{ removed: boolean }> {
  return api.delete<{ removed: boolean }>(
    `/api/v1/command-center/zones/${encodeURIComponent(assetId)}`,
  );
}

// ── Network exposure (M16 truth, M18 read surfaces) ──────────────────────────

export interface PortExposure {
  port: number;
  transport: string;
  asset_count: number;
  observation_count: number;
  last_observed_at: string;
}

export interface ServiceExposure {
  service: string;
  validator_id: string;
  asset_count: number;
  observation_count: number;
  last_observed_at: string;
}

export interface PortAsset {
  asset_id: string;
  observation_count: number;
  last_observed_at: string;
  asset_name: string;
}

export interface NetworkDriftEvent {
  id: string;
  category: string;
  summary: string;
  policy_id: string;
  run_id: string;
  detected_at: string;
  severity: string;
  target_asset_id: string;
  target_asset_name: string;
}

export function getTopOpenPorts(limit = 25): Promise<PortExposure[]> {
  return api.get<PortExposure[]>(`/api/v1/network-security/top-ports?limit=${limit}`);
}

export function getAssetsForPort(port: number): Promise<PortAsset[]> {
  return api.get<PortAsset[]>(`/api/v1/network-security/top-ports/${port}/assets`);
}

export function getServiceExposure(limit = 50): Promise<ServiceExposure[]> {
  return api.get<ServiceExposure[]>(`/api/v1/network-security/service-exposure?limit=${limit}`);
}

export function getNetworkDrift(limit = 50): Promise<NetworkDriftEvent[]> {
  return api.get<NetworkDriftEvent[]>(`/api/v1/network-security/drift?limit=${limit}`);
}

export const INTEGRATION_LABELS: Record<string, string> = {
  firewall: "Firewall / IDS / IPS",
  network_telemetry: "Network Telemetry (Bandwidth / Flow)",
  connectivity: "ISP / Connectivity",
  backup_dr: "Backup & Disaster Recovery",
  threat_intel: "Threat Intelligence",
  geolocation: "Geolocation Enrichment",
};

export const ZONE_LABELS: Record<string, string> = {
  internet_edge: "Internet Edge",
  dmz: "DMZ",
  internal: "Internal",
  management: "Management",
  cloud: "Cloud",
  restricted: "Restricted",
  unknown: "Unknown",
};
