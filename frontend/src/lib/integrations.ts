import { api } from "@/lib/api";

export interface CredentialFieldSpec {
  name: string;
  label: string;
  required: boolean;
  help_text: string;
  is_multiline: boolean;
}

export interface ConfigFieldSpec {
  name: string;
  label: string;
  required: boolean;
  default: string | null;
  help_text: string;
}

export interface ConnectorDocs {
  purpose: string;
  supported_features: string[];
  required_credentials: string;
  required_permissions: string;
  required_vendor_configuration: string;
  validation_process: string;
  connectivity_test: string;
  health_check: string;
  synchronization_strategy: string;
  troubleshooting_guide: string;
  common_failure_scenarios: string;
  recovery_steps: string;
  required_scopes: string[];
  callback_urls: string[];
  firewall_notes: string;
}

export interface ConnectorPlugin {
  connector_id: string;
  display_name: string;
  category: string;
  auth_model: string;
  credential_fields: CredentialFieldSpec[];
  config_fields: ConfigFieldSpec[];
  docs: ConnectorDocs;
}

export interface ConnectorRegistration {
  connector_id: string;
  tenant_id: string;
  connector_type: string;
  display_name: string;
  status: string;
  circuit_state: string;
  credential_vault_key: string;
  credential_type: string;
}

export interface ConnectorHealthEntry {
  status: string;
  response_time_ms: number | null;
  checked_at: string;
  error_detail: string | null;
}

export interface VaultBackend {
  backend_id: string;
  tenant_id: string;
  name: string;
  backend_type: string;
  is_default: boolean;
}

export function listCatalog(): Promise<ConnectorPlugin[]> {
  return api.get<ConnectorPlugin[]>("/api/v1/integration-hub/catalog");
}

export function listConnectors(): Promise<ConnectorRegistration[]> {
  return api.get<ConnectorRegistration[]>("/api/v1/integration-hub/connectors");
}

export function listVaultBackends(): Promise<VaultBackend[]> {
  return api.get<VaultBackend[]>("/api/v1/vault-backends");
}

export function createDefaultVaultBackend(): Promise<VaultBackend> {
  return api.post<VaultBackend>("/api/v1/vault-backends", {
    name: "default",
    backend_type: "LOCAL_ENCRYPTED",
    config: {},
    is_default: true,
  });
}

export function registerConnectorWithCredential(input: {
  connector_id: string;
  display_name: string;
  plaintext_secret: string;
  vault_backend_id: string;
  owner_principal_id: string;
  configuration: Record<string, string>;
}): Promise<ConnectorRegistration> {
  return api.post<ConnectorRegistration>(
    "/api/v1/integration-hub/connectors/register-with-credential",
    input
  );
}

export function testConnection(connectorId: string): Promise<{ status: string }> {
  return api.post<{ status: string }>(
    `/api/v1/integration-hub/connectors/${connectorId}/test-connection`
  );
}

export function getHealthHistory(connectorId: string): Promise<ConnectorHealthEntry[]> {
  return api.get<ConnectorHealthEntry[]>(
    `/api/v1/integration-hub/connectors/${connectorId}/health`
  );
}

export function disableConnector(connectorId: string): Promise<ConnectorRegistration> {
  return api.delete<ConnectorRegistration>(
    `/api/v1/integration-hub/connectors/${connectorId}`,
    { disabled_by: "admin", reason: "disabled via console" }
  );
}

export function statusTone(status: string): "critical" | "high" | "warning" | "ok" | "neutral" {
  switch (status.toUpperCase()) {
    case "HEALTHY":
    case "REGISTERED":
      return "ok";
    case "DEGRADED":
      return "warning";
    case "UNHEALTHY":
      return "critical";
    case "DISABLED":
      return "neutral";
    default:
      return "neutral";
  }
}
