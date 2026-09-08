/**
 * Platform Runtime API client — M27/M31.
 *
 * Backs the Super Admin Command Center's infrastructure-health panel.
 * No frontend consumer existed for `/api/v1/runtime/*` before this
 * (confirmed by grep). These endpoints are the real source for
 * platform health, circuit breakers, DLQ, background worker/replay
 * status, and projection checkpoints — the platform capabilities
 * this milestone asked for are not fabricated, they already exist in
 * `redforge.api.v1.runtime`.
 */
import { api } from "@/lib/api";

export interface RuntimeStatus {
  phase: string;
  overall_health: string;
  component_count: number;
  unhealthy_components: string[];
  circuit_states: Record<string, string>;
  dlq_total_entries: number;
  metrics_sample_count: number;
  checked_at: string;
  /** ADR-0009 — the backend's own `Settings.product_edition`, exposed
   * so the frontend can detect a build/deploy edition mismatch. See
   * `@/lib/editionMismatch`. */
  product_edition: string;
}

export interface ComponentHealth {
  component_id: string;
  status: string;
  message: string;
  checked_at: string;
}

export interface AggregatedHealth {
  overall_status: string;
  components: ComponentHealth[];
  checked_at: string;
}

export interface DLQEntry {
  entry_id: string;
  source_projection: string;
  event_id: string;
  event_type: string;
  error_message: string;
  retry_count: number;
}

export interface DLQList {
  entries: DLQEntry[];
  total: number;
}

export interface ReplayStatus {
  worker_running: boolean;
  replayed: number;
  failed: number;
  skipped: number;
  in_flight: number;
}

export interface Checkpoint {
  projection_name: string;
  last_global_position: number;
}

export interface CheckpointsResponse {
  projections: Checkpoint[];
  total: number;
}

export function getRuntimeStatus(): Promise<RuntimeStatus> {
  return api.get<RuntimeStatus>("/api/v1/runtime/status");
}

export function getAggregatedHealth(): Promise<AggregatedHealth> {
  return api.get<AggregatedHealth>("/api/v1/runtime/health");
}

export function getCircuitStates(): Promise<Record<string, string>> {
  return api.get<Record<string, string>>("/api/v1/runtime/circuits");
}

export function getDlqEntries(): Promise<DLQList> {
  return api.get<DLQList>("/api/v1/runtime/dlq");
}

export function getReplayStatus(): Promise<ReplayStatus> {
  return api.get<ReplayStatus>("/api/v1/runtime/replay/status");
}

export function getCheckpoints(): Promise<CheckpointsResponse> {
  return api.get<CheckpointsResponse>("/api/v1/runtime/checkpoints");
}
