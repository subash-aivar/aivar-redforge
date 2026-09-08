/**
 * Security Operations Command Center API client — M15.
 *
 * organization_id is never sent by the client — the backend always
 * derives it from the caller's verified token, same invariant as
 * every other M10-M14 client in this codebase. Enums (source domain,
 * importance, bounded period) are closed literal unions here, not
 * free text.
 */
import { api } from "./api";

export type SourceDomain =
  | "authorization"
  | "validation"
  | "continuous_validation"
  | "security_drift"
  | "security_condition"
  | "security_correlation"
  | "runtime"
  // network_security is emitted by the backend (M16 network run/policy
  // lifecycle events and, since M18, network drift events merged into the
  // feed); the client union previously omitted it.
  | "network_security"
  // ddos (M19), behavior (M20), investigation (M21) — real backend
  // source domains (see redforge.domain.security_operations.value_objects
  // .SourceDomain) the client union had drifted out of sync with.
  | "ddos"
  | "behavior"
  | "investigation"
  | "unknown";

export type OperationalImportance = "info" | "notice" | "warning" | "high" | "critical";
export type BoundedPeriod = "1h" | "24h" | "7d" | "30d";
export type RuntimeComponentStatus = "healthy" | "degraded" | "unhealthy" | "unknown";
export type ExecutionPhase =
  | "authorization"
  | "resolution"
  | "discovery"
  | "service_validation"
  | "adaptive_validation"
  | "protocol_validation"
  | "condition_processing"
  | "correlation"
  | "snapshot"
  | "drift"
  | "completed"
  | "unknown";

export interface OperationalEvent {
  cursor: string;
  event_id: string;
  organization_id: string;
  source_domain: SourceDomain;
  importance: OperationalImportance;
  title: string;
  summary: string;
  entity_type: string;
  entity_id: string;
  occurred_at: string;
  schema_version: number;
}

export interface SecurityOperationsSummary {
  period: string;
  canonical_assets: number;
  critical_high_conditions: number;
  active_correlations: number;
  runtime_unhealthy_components: number;
  // Full-only fields (ai_targets / continuous_validation / validation_execution
  // bounded contexts) — `null` for the network_defense edition, never a
  // fabricated 0. See backend SecurityOperationsSummaryDTO.
  active_targets: number | null;
  active_continuous_validation_policies: number | null;
  validations_running: number | null;
  validations_blocked_in_period: number | null;
  validations_failed_in_period: number | null;
  drift_events_in_period: number | null;
}

export interface ExecutionTelemetrySummary {
  id: string;
  organization_id: string;
  target_id: string;
  trigger: string;
  continuous_policy_id: string | null;
  profile: string;
  state: string;
  phase: ExecutionPhase;
  latest_event_title: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
}

export interface TelemetryTimelineEntry {
  phase: ExecutionPhase;
  event_type: string;
  title: string;
  occurred_at: string;
}

export interface ExecutionTelemetryDetail {
  summary: ExecutionTelemetrySummary;
  timeline: TelemetryTimelineEntry[];
  result_summary: string;
}

export interface RuntimeComponent {
  component_id: string;
  status: RuntimeComponentStatus;
  message: string;
  checked_at: string;
}

export interface ListChangesParams {
  period?: BoundedPeriod;
  source_domain?: SourceDomain;
  importance?: OperationalImportance;
  entity_id?: string;
  limit?: number;
  offset?: number;
}

export interface ListExecutionsParams {
  state?: string;
  trigger?: string;
  target_id?: string;
  limit?: number;
  offset?: number;
}

function toQueryString(params: object): string {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params as Record<string, unknown>)) {
    if (value !== undefined && value !== "") query.set(key, String(value));
  }
  const qs = query.toString();
  return qs ? `?${qs}` : "";
}

export async function getSummary(
  period: BoundedPeriod = "24h"
): Promise<SecurityOperationsSummary> {
  return api.get<SecurityOperationsSummary>(
    `/api/v1/security-operations/summary${toQueryString({ period })}`
  );
}

export async function listChanges(
  params: ListChangesParams = {}
): Promise<OperationalEvent[]> {
  return api.get<OperationalEvent[]>(
    `/api/v1/security-operations/changes${toQueryString(params)}`
  );
}

export async function listEvents(
  sinceCursor?: string,
  limit?: number
): Promise<OperationalEvent[]> {
  return api.get<OperationalEvent[]>(
    `/api/v1/security-operations/events${toQueryString({ since_cursor: sinceCursor, limit })}`
  );
}

export async function listExecutions(
  params: ListExecutionsParams = {}
): Promise<ExecutionTelemetrySummary[]> {
  return api.get<ExecutionTelemetrySummary[]>(
    `/api/v1/security-operations/executions${toQueryString(params)}`
  );
}

export async function getExecutionDetail(id: string): Promise<ExecutionTelemetryDetail> {
  return api.get<ExecutionTelemetryDetail>(`/api/v1/security-operations/executions/${id}`);
}

export async function listRuntimeComponents(): Promise<RuntimeComponent[]> {
  return api.get<RuntimeComponent[]>("/api/v1/security-operations/runtime");
}
