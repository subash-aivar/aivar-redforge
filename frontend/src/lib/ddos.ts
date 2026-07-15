/**
 * AIVAR RedForge — DDoS Defense Center API client (M19).
 *
 * Every call is tenant-scoped by the backend from the bearer token;
 * organization_id is never sent from the client.
 *
 * All data returned from these endpoints is derived from canonical
 * telemetry_events aggregation. No synthetic or fabricated values.
 */

import { api } from "@/lib/api";

// ── Protected Resources ───────────────────────────────────────────────────────

export interface ProtectedResource {
  id: string;
  name: string;
  description: string;
  scope_type: string;
  scope_value: string | null;
  criticality: string;
  monitored_ports: number[] | null;
  monitoring_enabled: boolean;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface DetectionPolicy {
  id: string;
  resource_id: string;
  enabled: boolean;
  profile: string;
  static_bps_threshold: number | null;
  static_pps_threshold: number | null;
  static_fps_threshold: number | null;
  window_seconds: number;
  min_breach_windows: number;
  quiet_period_windows: number;
  mitigation_mode: string;
  suppression_windows: unknown[] | null;
  created_at: string;
  updated_at: string;
}

export function listProtectedResources(): Promise<ProtectedResource[]> {
  return api.get<ProtectedResource[]>("/api/v1/ddos/resources");
}

export function getProtectedResource(id: string): Promise<ProtectedResource> {
  return api.get<ProtectedResource>(`/api/v1/ddos/resources/${id}`);
}

export function createProtectedResource(data: {
  name: string;
  description?: string;
  scope_type?: string;
  scope_value?: string;
  criticality?: string;
  monitored_ports?: number[];
}): Promise<ProtectedResource> {
  return api.post<ProtectedResource>("/api/v1/ddos/resources", data);
}

export function deleteProtectedResource(id: string): Promise<void> {
  return api.delete<void>(`/api/v1/ddos/resources/${id}`);
}

export function getDetectionPolicy(resourceId: string): Promise<DetectionPolicy> {
  return api.get<DetectionPolicy>(`/api/v1/ddos/resources/${resourceId}/policy`);
}

// ── Incidents ─────────────────────────────────────────────────────────────────

export interface DDoSIncident {
  id: string;
  resource_id: string;
  resource_name: string;
  status: string;
  severity: string;
  classification: string;
  first_detected_at: string;
  last_updated_at: string;
  peak_at: string | null;
  resolved_at: string | null;
  peak_bytes_per_second: number | null;
  peak_packets_per_second: number | null;
  peak_flows_per_second: number | null;
  peak_unique_src_ips: number | null;
  peak_deviation_multiplier: number | null;
  consecutive_quiet_windows: number;
  opening_evidence: Record<string, unknown>;
  latest_evidence: Record<string, unknown>;
}

export interface IncidentTimelineEvent {
  id: string;
  event_type: string;
  occurred_at: string;
  description: string;
  payload: Record<string, unknown>;
  actor_id: string | null;
}

export function listIncidents(params?: {
  status?: string[];
  resource_id?: string;
  limit?: number;
  offset?: number;
}): Promise<DDoSIncident[]> {
  const qs = new URLSearchParams();
  if (params?.status) params.status.forEach((s) => qs.append("status", s));
  if (params?.resource_id) qs.set("resource_id", params.resource_id);
  if (params?.limit) qs.set("limit", String(params.limit));
  if (params?.offset) qs.set("offset", String(params.offset));
  const q = qs.toString();
  return api.get<DDoSIncident[]>(`/api/v1/ddos/incidents${q ? `?${q}` : ""}`);
}

export function listActiveIncidents(): Promise<DDoSIncident[]> {
  return api.get<DDoSIncident[]>("/api/v1/ddos/incidents/active");
}

export function getIncident(id: string): Promise<DDoSIncident> {
  return api.get<DDoSIncident>(`/api/v1/ddos/incidents/${id}`);
}

export function getIncidentTimeline(id: string): Promise<IncidentTimelineEvent[]> {
  return api.get<IncidentTimelineEvent[]>(`/api/v1/ddos/incidents/${id}/timeline`);
}

export function closeIncident(id: string): Promise<DDoSIncident> {
  return api.post<DDoSIncident>(`/api/v1/ddos/incidents/${id}/close`, { reason: "" });
}

// ── Mitigation ────────────────────────────────────────────────────────────────

export interface MitigationRecommendation {
  id: string;
  incident_id: string;
  recommendation_type: string;
  description: string;
  recommendation_detail: Record<string, unknown>;
  approval_status: string;
  approved_by: string | null;
  approved_at: string | null;
  rejected_by: string | null;
  rejection_reason: string | null;
  execution_status: string;
  executed_at: string | null;
  provider_type: string | null;
  expires_at: string | null;
  created_at: string;
}

export function listPendingRecommendations(): Promise<MitigationRecommendation[]> {
  return api.get<MitigationRecommendation[]>("/api/v1/ddos/mitigation/pending");
}

export function listIncidentRecommendations(incidentId: string): Promise<MitigationRecommendation[]> {
  return api.get<MitigationRecommendation[]>(`/api/v1/ddos/incidents/${incidentId}/mitigation`);
}

export function approveRecommendation(recId: string): Promise<MitigationRecommendation> {
  return api.post<MitigationRecommendation>(`/api/v1/ddos/mitigation/${recId}/approve`, {});
}

export function rejectRecommendation(recId: string, reason: string): Promise<MitigationRecommendation> {
  return api.post<MitigationRecommendation>(`/api/v1/ddos/mitigation/${recId}/reject`, { reason });
}

// ── Traffic Windows ───────────────────────────────────────────────────────────

export interface ObservationWindow {
  id: string;
  resource_id: string;
  window_start_ts: string;
  window_end_ts: string;
  event_count: number;
  total_bytes_in: number | null;
  total_bytes_out: number | null;
  unique_src_ips: number;
  protocol_counts: Record<string, number>;
  alert_count: number;
  detection_fired: boolean;
  severity: string | null;
  classification: string | null;
  incident_id: string | null;
}

export function listTrafficWindows(resourceId: string, hours?: number): Promise<ObservationWindow[]> {
  const qs = new URLSearchParams({ resource_id: resourceId });
  if (hours) qs.set("hours", String(hours));
  return api.get<ObservationWindow[]>(`/api/v1/ddos/traffic/windows?${qs}`);
}

// ── Posture ───────────────────────────────────────────────────────────────────

export interface DDoSPosture {
  protected_resource_count: number;
  active_incident_count: number;
  pending_recommendation_count: number;
  active_incident_severity_counts: Record<string, number>;
  active_incidents: Array<{
    id: string;
    resource_id: string;
    resource_name: string;
    status: string;
    severity: string;
    classification: string;
    first_detected_at: string;
  }>;
}

export function getDDoSPosture(): Promise<DDoSPosture> {
  return api.get<DDoSPosture>("/api/v1/ddos/posture");
}

// ── Helpers ───────────────────────────────────────────────────────────────────

export function severityColor(severity: string): string {
  switch (severity?.toUpperCase()) {
    case "CRITICAL": return "text-red-400 border-red-800 bg-red-950";
    case "HIGH":     return "text-orange-400 border-orange-800 bg-orange-950";
    case "MEDIUM":   return "text-yellow-400 border-yellow-800 bg-yellow-950";
    case "LOW":      return "text-blue-400 border-blue-800 bg-blue-950";
    default:         return "text-gray-400 border-gray-700 bg-gray-800";
  }
}

export function statusColor(status: string): string {
  switch (status?.toUpperCase()) {
    case "DETECTED":   return "text-red-300 border-red-900 bg-red-950";
    case "ACTIVE":     return "text-orange-300 border-orange-900 bg-orange-950";
    case "ESCALATED":  return "text-red-400 border-red-800 bg-red-900";
    case "MITIGATING": return "text-yellow-300 border-yellow-900 bg-yellow-950";
    case "MONITORING": return "text-blue-300 border-blue-900 bg-blue-950";
    case "RESOLVED":   return "text-emerald-300 border-emerald-900 bg-emerald-950";
    case "CLOSED":     return "text-gray-400 border-gray-700 bg-gray-800";
    default:           return "text-gray-400 border-gray-700 bg-gray-800";
  }
}

export function formatBps(bps: number | null): string {
  if (bps == null) return "—";
  if (bps >= 1e9) return `${(bps / 1e9).toFixed(2)} Gbps`;
  if (bps >= 1e6) return `${(bps / 1e6).toFixed(2)} Mbps`;
  if (bps >= 1e3) return `${(bps / 1e3).toFixed(1)} Kbps`;
  return `${bps.toFixed(0)} bps`;
}

export function formatPps(pps: number | null): string {
  if (pps == null) return "—";
  if (pps >= 1e6) return `${(pps / 1e6).toFixed(2)} Mpps`;
  if (pps >= 1e3) return `${(pps / 1e3).toFixed(1)} Kpps`;
  return `${pps.toFixed(0)} pps`;
}
