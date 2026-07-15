/**
 * AIVAR RedForge — Behavioral Security NDR API client (M20).
 *
 * All data is derived from canonical telemetry_events.
 * No synthetic or fabricated values are introduced.
 *
 * Supported detections (from telemetry_events schema):
 *   NEW_DESTINATION, RARE_DESTINATION, HIGH_FAN_OUT,
 *   PORT_SCAN_SUSPECTED, BEACONING_SUSPECTED,
 *   ABNORMAL_OUTBOUND_TRANSFER, UNUSUAL_EAST_WEST, UNUSUAL_SERVICE_ACCESS
 *
 * Unsupported (honest):
 *   User auth anomalies, impossible travel, TCP fail ratio, true lateral movement
 */

import { api } from "@/lib/api";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface BehaviorPosture {
  active_detections: number;
  critical_high_detections: number;
  detections_by_severity: Record<string, number>;
  detections_by_type: Record<string, number>;
  monitored_entities: number;
  established_baselines: number;
  recent_detections: BehaviorDetection[];
}

export interface BehaviorDetection {
  id: string;
  entity_id: string;
  entity_type: string;
  detection_type: string;
  status: string;
  severity: string;
  detected_at: string;
  last_seen_at: string;
  observation_count: number;
  secondary_entity_id: string | null;
  evidence: Record<string, unknown>;
  notes?: string;
  timeline?: DetectionEvent[];
}

export interface DetectionEvent {
  id: string;
  event_type: string;
  detail: string;
  actor_user_id: string | null;
  created_at: string;
}

export interface EntityRisk {
  entity_id: string;
  entity_type: string;
  baseline_confidence: string;
  window_count: number;
  active_detections: number;
  risk_level: string;
  top_severity: string | null;
  updated_at: string;
}

export interface EntityBehavior {
  entity_id: string;
  entity_type: string;
  baseline_confidence: string;
  window_count: number;
  p75_unique_dst_ips: number;
  p75_bytes_out: number | null;
  p75_event_count: number;
  seen_dst_ip_count: number;
  detections: BehaviorDetection[];
  recent_observations: ObservationWindow[];
}

export interface ObservationWindow {
  window_start_ts: string;
  window_end_ts: string;
  event_count: number;
  unique_dst_ips: number;
  unique_dst_ports: number;
  total_bytes_out: number | null;
}

export interface NetworkRelationship {
  src_ip: string;
  dst_ip: string;
  dst_port: number | null;
  protocol: string | null;
  event_count: number;
  total_bytes_out: number | null;
  last_seen: string | null;
  relationship_type: string;
}

export interface NetworkRelationships {
  edges: NetworkRelationship[];
  hours: number;
  total: number;
}

export interface BehaviorHealth {
  monitored_entities: number;
  established_baselines: number;
  cold_start_entities: number;
  active_detections: number;
  severity_breakdown: Record<string, number>;
  supported_detections: string[];
  unsupported_detections: string[];
}

// ── API calls ─────────────────────────────────────────────────────────────────

export function getBehaviorPosture(): Promise<BehaviorPosture> {
  return api.get<BehaviorPosture>("/api/v1/behavior/posture");
}

export function listDetections(params?: {
  status?: string;
  entity_id?: string;
  limit?: number;
  offset?: number;
}): Promise<BehaviorDetection[]> {
  const q = new URLSearchParams();
  if (params?.status) q.set("status", params.status);
  if (params?.entity_id) q.set("entity_id", params.entity_id);
  if (params?.limit) q.set("limit", String(params.limit));
  if (params?.offset) q.set("offset", String(params.offset));
  const qs = q.toString();
  return api.get<BehaviorDetection[]>(`/api/v1/behavior/detections${qs ? `?${qs}` : ""}`);
}

export function getDetection(id: string): Promise<BehaviorDetection> {
  return api.get<BehaviorDetection>(`/api/v1/behavior/detections/${id}`);
}

export function closeDetection(id: string, notes = ""): Promise<{ status: string }> {
  return api.post<{ status: string }>(`/api/v1/behavior/detections/${id}/close`, { notes });
}

export function listEntities(limit = 200): Promise<EntityRisk[]> {
  return api.get<EntityRisk[]>(`/api/v1/behavior/entities?limit=${limit}`);
}

export function getEntityBehavior(entityId: string): Promise<EntityBehavior> {
  return api.get<EntityBehavior>(`/api/v1/behavior/entities/${encodeURIComponent(entityId)}`);
}

export function getNetworkRelationships(hours = 24, limit = 100): Promise<NetworkRelationships> {
  return api.get<NetworkRelationships>(
    `/api/v1/behavior/network/relationships?hours=${hours}&limit=${limit}`
  );
}

export function getBehaviorHealth(): Promise<BehaviorHealth> {
  return api.get<BehaviorHealth>("/api/v1/behavior/health");
}

// ── Severity / status helpers ─────────────────────────────────────────────────

export function severityColor(sev: string): string {
  switch (sev) {
    case "CRITICAL": return "border-red-500 bg-red-950 text-red-300";
    case "HIGH": return "border-orange-500 bg-orange-950 text-orange-300";
    case "MEDIUM": return "border-yellow-500 bg-yellow-950 text-yellow-300";
    case "LOW": return "border-blue-500 bg-blue-950 text-blue-300";
    case "INFORMATIONAL": return "border-gray-500 bg-gray-900 text-gray-300";
    default: return "border-gray-600 bg-gray-900 text-gray-400";
  }
}

export function severityDot(sev: string): string {
  switch (sev) {
    case "CRITICAL": return "bg-red-500";
    case "HIGH": return "bg-orange-500";
    case "MEDIUM": return "bg-yellow-400";
    case "LOW": return "bg-blue-400";
    case "INFORMATIONAL": return "bg-gray-400";
    default: return "bg-gray-600";
  }
}

export function statusColor(st: string): string {
  switch (st) {
    case "DETECTED": return "border-purple-500 bg-purple-950 text-purple-300";
    case "ACTIVE": return "border-red-500 bg-red-950 text-red-300";
    case "INVESTIGATING": return "border-yellow-500 bg-yellow-950 text-yellow-300";
    case "MONITORING": return "border-blue-500 bg-blue-950 text-blue-300";
    case "RESOLVED": return "border-green-500 bg-green-950 text-green-300";
    case "CLOSED": return "border-gray-600 bg-gray-900 text-gray-400";
    default: return "border-gray-600 bg-gray-900 text-gray-400";
  }
}

export function riskColor(r: string): string {
  switch (r) {
    case "CRITICAL": return "text-red-400";
    case "HIGH": return "text-orange-400";
    case "MEDIUM": return "text-yellow-400";
    case "LOW": return "text-blue-400";
    default: return "text-gray-500";
  }
}

export function detectionTypeLabel(t: string): string {
  const labels: Record<string, string> = {
    NEW_DESTINATION: "New Destination",
    RARE_DESTINATION: "Rare Destination",
    HIGH_FAN_OUT: "High Fan-Out",
    PORT_SCAN_SUSPECTED: "Port Scan Suspected",
    BEACONING_SUSPECTED: "Beaconing Suspected",
    ABNORMAL_OUTBOUND_TRANSFER: "Abnormal Outbound Transfer",
    UNUSUAL_EAST_WEST: "Unusual East-West",
    UNUSUAL_SERVICE_ACCESS: "Unusual Service Access",
  };
  return labels[t] ?? t;
}

export function formatBytes(b: number | null | undefined): string {
  if (b == null) return "—";
  if (b >= 1e9) return `${(b / 1e9).toFixed(1)} GB`;
  if (b >= 1e6) return `${(b / 1e6).toFixed(1)} MB`;
  if (b >= 1e3) return `${(b / 1e3).toFixed(1)} KB`;
  return `${b} B`;
}

export function baselineConfidenceLabel(c: string): string {
  const labels: Record<string, string> = {
    COLD_START: "Cold Start",
    INSUFFICIENT_DATA: "Insufficient Data",
    ESTABLISHED: "Established",
    DEGRADED: "Degraded",
  };
  return labels[c] ?? c;
}
