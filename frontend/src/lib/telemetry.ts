/**
 * Telemetry ingestion and query API client — M18.
 *
 * organization_id is always derived from the caller's verified token —
 * never accepted from the client. Sensor token_ref is always an env-var
 * name or vault path, never a raw credential.
 */
import { api } from "@/lib/api";

// ── Sensors ────────────────────────────────────────────────────────────────

export interface Sensor {
  id: string;
  name: string;
  format: string;
  description: string;
  enabled: boolean;
  created_at: string;
}

export function listSensors(): Promise<Sensor[]> {
  return api.get<Sensor[]>("/api/v1/telemetry/sensors");
}

export interface RegisterSensorInput {
  name: string;
  format: string;
  description?: string;
  token_ref?: string | null;
}

export function registerSensor(input: RegisterSensorInput): Promise<Sensor> {
  return api.post<Sensor>("/api/v1/telemetry/sensors", input);
}

export function deleteSensor(sensorId: string): Promise<void> {
  return api.delete<void>(`/api/v1/telemetry/sensors/${encodeURIComponent(sensorId)}`);
}

// ── Events ─────────────────────────────────────────────────────────────────

export interface TelemetryEvent {
  id: string;
  sensor_id: string;
  sensor_name: string;
  source_event_id: string;
  format: string;
  event_type: string;
  event_ts: string;
  src_ip: string | null;
  dst_ip: string | null;
  src_port: number | null;
  dst_port: number | null;
  protocol: string | null;
  action: string | null;
  severity: string | null;
  signature: string | null;
  signature_id: string | null;
  bytes_in: number | null;
  bytes_out: number | null;
  packets_in: number | null;
  packets_out: number | null;
  enrichment_state: string;
  ingested_at: string;
}

export function listTelemetryEvents(
  params: {
    sensor_id?: string;
    event_type?: string;
    limit?: number;
    offset?: number;
  } = {},
): Promise<TelemetryEvent[]> {
  const qs = new URLSearchParams();
  if (params.sensor_id) qs.set("sensor_id", params.sensor_id);
  if (params.event_type) qs.set("event_type", params.event_type);
  if (params.limit != null) qs.set("limit", String(params.limit));
  if (params.offset != null) qs.set("offset", String(params.offset));
  const q = qs.toString();
  return api.get<TelemetryEvent[]>(`/api/v1/telemetry/events${q ? `?${q}` : ""}`);
}

// ── Bandwidth / traffic ────────────────────────────────────────────────────

export interface BandwidthSummary {
  period_hours: number;
  total_bytes_in: number | null;
  total_bytes_out: number | null;
  total_packets_in: number | null;
  total_packets_out: number | null;
  flow_count: number;
  top_talkers: Array<{ src_ip: string; bytes_sent: number; flow_count: number }>;
  top_destination_ports: Array<{
    dst_port: number;
    protocol: string | null;
    event_count: number;
  }>;
  has_real_data: boolean;
}

export function getBandwidthSummary(periodHours = 24): Promise<BandwidthSummary> {
  return api.get<BandwidthSummary>(
    `/api/v1/telemetry/bandwidth?period_hours=${periodHours}`,
  );
}

// ── Geo activity ────────────────────────────────────────────────────────────

export interface GeoActivityPoint {
  ip: string;
  country: string | null;
  country_code: string | null;
  region: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
  asn: string | null;
  network_prefix: string | null;
  organization: string | null;
  rir_source: string | null;
  geo_provider: string | null;
  asn_provider: string | null;
  first_seen_at: string;
  last_seen_at: string;
  reputation_providers: string[];
}

export function listGeoActivity(limit = 500): Promise<GeoActivityPoint[]> {
  return api.get<GeoActivityPoint[]>(
    `/api/v1/threat-intel/geo-activity?limit=${limit}`,
  );
}
