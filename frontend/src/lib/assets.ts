/**
 * Asset inventory & connector API client — M3.
 *
 * Tenant-scoped throughout via the existing bearer-token session; no
 * organization_id is ever supplied client-side.
 */
import { api } from "./api";

export interface Asset {
  id: string;
  organization_id: string;
  asset_type: string;
  name: string;
  description: string;
  external_id: string;
  discovery_source: string;
  lifecycle_stage: string;
  health_status: string;
  first_observed_at: string;
  last_observed_at: string;
  relationship_count: number;
  associated_target_id: string | null;
}

export interface AssetRelationship {
  relationship_id: string;
  target_asset_id: string;
  relationship_type: string;
  label: string;
}

export interface Connector {
  id: string;
  organization_id: string;
  connector_type: string;
  name: string;
  status: string;
  last_discovery_status: string | null;
  last_discovery_completed_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface DiscoveryRun {
  job_id: string;
  connector_id: string;
  status: string;
  started_at: string;
  completed_at: string | null;
  assets_discovered: number;
  assets_normalized: number;
  assets_failed: number;
  error_message: string | null;
}

export async function listAssets(): Promise<Asset[]> {
  return api.get<Asset[]>("/api/v1/assets?limit=100");
}

export async function getAsset(assetId: string): Promise<Asset> {
  return api.get<Asset>(`/api/v1/assets/${assetId}`);
}

export async function getAssetRelationships(assetId: string): Promise<AssetRelationship[]> {
  return api.get<AssetRelationship[]>(`/api/v1/assets/${assetId}/relationships`);
}

export async function listConnectors(): Promise<Connector[]> {
  return api.get<Connector[]>("/api/v1/connectors");
}

export async function registerConnector(name: string, description: string): Promise<Connector> {
  return api.post<Connector>("/api/v1/connectors", { name, description });
}

export async function enableConnector(connectorId: string): Promise<Connector> {
  return api.post<Connector>(`/api/v1/connectors/${connectorId}/enable`);
}

export async function disableConnector(connectorId: string): Promise<Connector> {
  return api.post<Connector>(`/api/v1/connectors/${connectorId}/disable`);
}

export async function startDiscovery(connectorId: string): Promise<DiscoveryRun> {
  return api.post<DiscoveryRun>(`/api/v1/connectors/${connectorId}/discover`);
}

export async function listDiscoveryRuns(connectorId: string): Promise<DiscoveryRun[]> {
  return api.get<DiscoveryRun[]>(`/api/v1/connectors/${connectorId}/discovery-runs`);
}
