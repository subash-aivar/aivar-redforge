import { api } from "@/lib/api";

export interface Incident {
  incident_id: string;
  tenant_id: string;
  title: string;
  description: string;
  phase: string;
  severity: string;
  trigger_type: string;
  classified_at: string | null;
  contained_at: string | null;
  eradicated_at: string | null;
  recovered_at: string | null;
  closed_at: string | null;
  resolution_type: string | null;
  timeline: Record<string, unknown>[];
}

export interface ActiveIncidentsDashboard {
  active_count: number;
  p1_count: number;
  p2_count: number;
  incidents: Incident[];
}

export function listIncidents(): Promise<Incident[]> {
  return api.get<Incident[]>("/api/v1/incident");
}

export function getActiveDashboard(): Promise<ActiveIncidentsDashboard> {
  return api.get<ActiveIncidentsDashboard>("/api/v1/incident/dashboard/active");
}

export function getIncident(incidentId: string): Promise<Incident> {
  return api.get<Incident>(`/api/v1/incident/${incidentId}`);
}

export function closeIncident(
  incidentId: string,
  resolutionType: string,
  actor = "analyst"
): Promise<Incident> {
  return api.post<Incident>(`/api/v1/incident/${incidentId}/close`, {
    resolution_type: resolutionType,
    actor,
  });
}

export function severityTone(
  severity: string
): "critical" | "high" | "warning" | "ok" | "neutral" {
  switch (severity.toUpperCase()) {
    case "P1":
    case "CRITICAL":
      return "critical";
    case "P2":
    case "HIGH":
      return "high";
    case "P3":
    case "MEDIUM":
      return "warning";
    default:
      return "neutral";
  }
}

export function phaseTone(phase: string): "critical" | "high" | "warning" | "ok" | "neutral" {
  switch (phase.toUpperCase()) {
    case "CLOSED":
    case "RECOVERED":
      return "ok";
    case "CONTAINED":
    case "ERADICATED":
      return "warning";
    default:
      return "critical";
  }
}
