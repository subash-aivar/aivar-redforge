/**
 * Cloud Security API client — M7.
 *
 * Read-only observations. Cloud account/resource assets themselves are
 * browsed via the existing generic Assets API (`@/lib/assets`,
 * filterable by asset_type) — not duplicated here.
 */
import { api } from "./api";

export interface CloudSecurityObservation {
  rule_id: string;
  title: string;
  summary: string;
  affected_asset_id: string;
}

export async function listCloudSecurityObservations(): Promise<CloudSecurityObservation[]> {
  return api.get<CloudSecurityObservation[]>("/api/v1/cloud-security/observations");
}

export interface RegisterCloudConnectorRequest {
  name: string;
  region: string;
  access_key_id: string;
  secret_access_key_credential_reference_id: string;
  session_token_credential_reference_id?: string;
  description?: string;
}

export async function registerCloudConnector(
  body: RegisterCloudConnectorRequest
): Promise<{ id: string }> {
  return api.post<{ id: string }>("/api/v1/connectors/cloud", body);
}
