import { api } from "@/lib/api";

export interface Integration {
  integration_id: string;
  tenant_id: string;
  name: string;
  integration_type: string;
  status: string;
  config: Record<string, unknown>;
  created_at: string;
  last_synced_at: string | null;
}

export interface IntegrationEvent {
  event_id: string;
  integration_id: string;
  event_type: string;
  status: string;
  payload_summary: string;
  created_at: string;
}

export function listIntegrations(): Promise<Integration[]> {
  return api.get<Integration[]>("/api/v1/integration-hub/integrations");
}

export function getIntegration(id: string): Promise<Integration> {
  return api.get<Integration>(`/api/v1/integration-hub/integrations/${id}`);
}

export function createIntegration(body: {
  name: string;
  integration_type: string;
  config: Record<string, unknown>;
}): Promise<Integration> {
  return api.post<Integration>("/api/v1/integration-hub/integrations", body);
}

export function enableIntegration(id: string): Promise<Integration> {
  return api.post<Integration>(`/api/v1/integration-hub/integrations/${id}/enable`, {});
}

export function disableIntegration(id: string): Promise<Integration> {
  return api.post<Integration>(`/api/v1/integration-hub/integrations/${id}/disable`, {});
}

export function syncIntegration(id: string): Promise<{ status: string }> {
  return api.post(`/api/v1/integration-hub/integrations/${id}/sync`, {});
}

export function listEvents(integrationId: string): Promise<IntegrationEvent[]> {
  return api.get<IntegrationEvent[]>(`/api/v1/integration-hub/integrations/${integrationId}/events`);
}
