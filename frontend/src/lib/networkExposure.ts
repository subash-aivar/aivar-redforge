/**
 * Network Exposure API client — M6.
 *
 * Read-only observations. Network/IP/host/device/service assets
 * themselves are browsed via the existing generic Assets API
 * (`@/lib/assets`, filterable by asset_type) — not duplicated here.
 */
import { api } from "./api";

export interface NetworkSecurityObservation {
  rule_id: string;
  title: string;
  summary: string;
  affected_asset_id: string;
}

export async function listNetworkExposureObservations(): Promise<NetworkSecurityObservation[]> {
  return api.get<NetworkSecurityObservation[]>("/api/v1/network-exposure/observations");
}

export interface RegisterNetworkConnectorRequest {
  name: string;
  network_cidr: string;
  ports: number[];
  description?: string;
}

export async function registerNetworkConnector(
  body: RegisterNetworkConnectorRequest
): Promise<{ id: string }> {
  return api.post<{ id: string }>("/api/v1/connectors/network", body);
}
