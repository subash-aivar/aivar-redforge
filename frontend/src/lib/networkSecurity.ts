/**
 * Advanced Network Security & Continuous Network Monitoring API client — M16.
 *
 * organization_id/requester_user_id are never sent by the client — the
 * backend always derives them from the caller's verified token. There
 * is no field anywhere in this client for a scanner flag, port range,
 * command, script, or exploit — only a target_asset_id (an existing
 * canonical NETWORK/IP_ADDRESS asset) and a closed profile string.
 */
import { api } from "./api";

export type NetworkValidationProfile =
  | "network_baseline"
  | "network_standard"
  | "network_deep_safe";
export type NetworkPolicyLifecycle = "draft" | "active" | "paused" | "disabled";
export type NetworkValidationCadence = "hourly" | "every_6_hours" | "daily" | "weekly";

export interface NetworkMonitoringPolicy {
  id: string;
  organization_id: string;
  target_asset_id: string;
  requester_user_id: string;
  profile: NetworkValidationProfile;
  cadence: NetworkValidationCadence;
  lifecycle: NetworkPolicyLifecycle;
  next_due_at: string | null;
  last_scheduled_at: string | null;
}

export interface NetworkRunResult {
  run_id: string;
  status: string;
  authorization_id: string | null;
  reachable_ports: number[];
  denied_addresses: string[];
}

export interface NetworkInventoryEntry {
  asset_id: string;
  address: string;
  address_classification: string;
  observed_services: string[];
  active_condition_count: number;
  last_observed_at: string;
  monitoring_status: string;
}

export interface NetworkAssetDetail {
  asset_id: string;
  address: string;
  address_classification: string;
  first_observed_at: string;
  last_observed_at: string;
  services: Record<string, string>[];
  active_conditions: Record<string, string>[];
  active_correlations: Record<string, string>[];
  monitoring_policy_id: string | null;
  monitoring_lifecycle: string | null;
}

export interface CreateNetworkPolicyInput {
  target_asset_id: string;
  profile?: NetworkValidationProfile;
  cadence?: NetworkValidationCadence;
}

export async function getInventory(
  limit = 100,
  offset = 0
): Promise<NetworkInventoryEntry[]> {
  return api.get<NetworkInventoryEntry[]>(
    `/api/v1/network-security/inventory?limit=${limit}&offset=${offset}`
  );
}

export async function getAssetDetail(assetId: string): Promise<NetworkAssetDetail> {
  return api.get<NetworkAssetDetail>(`/api/v1/network-security/assets/${assetId}`);
}

export async function createMonitoringPolicy(
  input: CreateNetworkPolicyInput
): Promise<NetworkMonitoringPolicy> {
  return api.post<NetworkMonitoringPolicy>(
    "/api/v1/network-security/monitoring-policies",
    input
  );
}

export async function listMonitoringPolicies(
  lifecycle?: NetworkPolicyLifecycle
): Promise<NetworkMonitoringPolicy[]> {
  const qs = lifecycle ? `?lifecycle=${lifecycle}` : "";
  return api.get<NetworkMonitoringPolicy[]>(
    `/api/v1/network-security/monitoring-policies${qs}`
  );
}

export async function activatePolicy(policyId: string): Promise<NetworkMonitoringPolicy> {
  return api.post<NetworkMonitoringPolicy>(
    `/api/v1/network-security/monitoring-policies/${policyId}/activate`,
    {}
  );
}

export async function pausePolicy(policyId: string): Promise<NetworkMonitoringPolicy> {
  return api.post<NetworkMonitoringPolicy>(
    `/api/v1/network-security/monitoring-policies/${policyId}/pause`,
    {}
  );
}

export async function resumePolicy(policyId: string): Promise<NetworkMonitoringPolicy> {
  return api.post<NetworkMonitoringPolicy>(
    `/api/v1/network-security/monitoring-policies/${policyId}/resume`,
    {}
  );
}

export async function disablePolicy(policyId: string): Promise<NetworkMonitoringPolicy> {
  return api.post<NetworkMonitoringPolicy>(
    `/api/v1/network-security/monitoring-policies/${policyId}/disable`,
    {}
  );
}

export async function runNow(policyId: string): Promise<NetworkRunResult> {
  return api.post<NetworkRunResult>(
    `/api/v1/network-security/monitoring-policies/${policyId}/run-now`,
    {}
  );
}
