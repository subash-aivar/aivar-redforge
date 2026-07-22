import { api } from "@/lib/api";

export interface RegulatoryNotification {
  notification_id: string;
  tenant_id: string;
  incident_id: string;
  regulation: string;
  authority_name: string;
  status: string;
  deadline: string;
  submitted_at: string | null;
  created_at: string;
}

export function listNotifications(): Promise<RegulatoryNotification[]> {
  return api.get<RegulatoryNotification[]>("/api/v1/regulatory-notification");
}

export function getNotification(id: string): Promise<RegulatoryNotification> {
  return api.get<RegulatoryNotification>(`/api/v1/regulatory-notification/${id}`);
}

export function createNotification(body: {
  incident_id: string;
  regulation: string;
  authority_name: string;
  deadline: string;
}): Promise<RegulatoryNotification> {
  return api.post<RegulatoryNotification>("/api/v1/regulatory-notification", body);
}

export function submitNotification(id: string): Promise<RegulatoryNotification> {
  return api.post<RegulatoryNotification>(`/api/v1/regulatory-notification/${id}/submit`, {});
}
