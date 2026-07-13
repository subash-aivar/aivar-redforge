/**
 * Gated Safe Active Validation API client — M11, extended for
 * Authorized Network Discovery & Adaptive Validation Orchestration —
 * M12, extended for Protocol-Aware Service Validation — M13.
 *
 * organization_id/requester_user_id are never sent by the client — the
 * backend always derives them from the caller's verified token. There
 * is no field for steps/ports/commands/validators — the client selects
 * a canonical target and one of the two closed profiles
 * (SAFE_ACTIVE_BASELINE_V1 or NETWORK_DISCOVERY_BASELINE_V1); the
 * server builds and, for the discovery profile, adaptively evolves the
 * entire execution plan, including which protocol validator (if any)
 * runs against each discovered candidate port. The client can never
 * submit step types, ports, adaptive rules, or validator names.
 */
import { api } from "./api";

export interface StepEvidenceItem {
  label: string;
  value: string;
  truncated: string;
}

export interface ValidationStep {
  id: string;
  step_type: string;
  order: number;
  status: string;
  started_at: string | null;
  completed_at: string | null;
  evidence: StepEvidenceItem[];
  error_category: string | null;
  /** "initial" (server's original plan) or "adaptive" (appended by a
   * closed, versioned rule after a discovery fact matched). */
  source: string;
  adaptive_rule_id: string | null;
  adaptive_rule_version: number | null;
  source_fact_ref: string | null;
  /** M13 — which ProtocolValidator (if any) produced this step's
   * outcome, and the resulting ProtocolValidationState
   * ("not_attempted" | "unreachable" | "inconclusive" | "hinted" |
   * "validated" | "error"). null for every non-protocol step type. */
  validator_id: string | null;
  validator_version: number | null;
  protocol_validation_state: string | null;
}

export interface PlanSummary {
  initial_step_count: number;
  adaptive_step_count: number;
  discovered_address_count: number;
  reachable_port_count: number;
  validated_service_count: number;
  condition_count: number;
}

export interface ValidationExecution {
  id: string;
  organization_id: string;
  target_id: string;
  requester_user_id: string;
  profile: string;
  status: string;
  policy_decision_id: string | null;
  policy_reason_code: string | null;
  cancellation_requested: boolean;
  created_at: string;
  updated_at: string;
  started_at: string | null;
  completed_at: string | null;
  failure_reason: string;
  steps: ValidationStep[];
  plan_summary: PlanSummary;
}

export interface ValidationExecutionSummary {
  pending: number;
  policy_checking: number;
  authorized: number;
  running: number;
  completed: number;
  partially_completed: number;
  failed: number;
  cancelled: number;
  denied: number;
}

export interface ExecutionEvent {
  id: string;
  execution_id: string;
  sequence: number;
  event_type: string;
  payload: Record<string, string>;
  occurred_at: string;
}

export interface ValidatedServiceEntry {
  port: string;
  hint: string;
  state: string;
  /** M13 — empty string for M12's own HTTP/HTTPS entries (no
   * validator-registry concept there); populated for the four M13
   * protocol candidates (ssh/mysql/postgresql/redis). */
  validator_id: string;
  validator_version: string;
}

export interface ValidationResult {
  execution_id: string;
  target_id: string;
  status: string;
  tcp_reachable: boolean | null;
  application_layer_validated: boolean | null;
  validation_basis: string | null;
  tls_protocol_version: string | null;
  http_status_code: string | null;
  conditions_observed: string[];
  failed_steps: string[];
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  /** Populated only for NETWORK_DISCOVERY_BASELINE_V1 executions. */
  discovered_addresses: string[];
  reachable_ports: number[];
  validated_services: ValidatedServiceEntry[];
  correlations_created: number | null;
  correlations_updated: number | null;
  correlations_resolved: number | null;
}

export interface ListExecutionsParams {
  status?: string;
  limit?: number;
  offset?: number;
}

export interface CreateExecutionInput {
  target_id: string;
  profile?: string;
}

export async function getExecutionSummary(): Promise<ValidationExecutionSummary> {
  return api.get<ValidationExecutionSummary>("/api/v1/validation-executions/summary");
}

export async function listExecutions(
  params: ListExecutionsParams = {}
): Promise<ValidationExecution[]> {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") query.set(key, String(value));
  }
  const qs = query.toString();
  return api.get<ValidationExecution[]>(`/api/v1/validation-executions${qs ? `?${qs}` : ""}`);
}

export async function getExecution(id: string): Promise<ValidationExecution> {
  return api.get<ValidationExecution>(`/api/v1/validation-executions/${id}`);
}

export async function createExecution(
  input: CreateExecutionInput
): Promise<ValidationExecution> {
  return api.post<ValidationExecution>("/api/v1/validation-executions", input);
}

export async function listExecutionEvents(
  id: string,
  afterSequence = 0,
  limit = 200
): Promise<ExecutionEvent[]> {
  const query = new URLSearchParams();
  query.set("after_sequence", String(afterSequence));
  query.set("limit", String(limit));
  return api.get<ExecutionEvent[]>(
    `/api/v1/validation-executions/${id}/events?${query.toString()}`
  );
}

export async function getExecutionResult(id: string): Promise<ValidationResult> {
  return api.get<ValidationResult>(`/api/v1/validation-executions/${id}/result`);
}

export async function cancelExecution(id: string): Promise<ValidationExecution> {
  return api.post<ValidationExecution>(`/api/v1/validation-executions/${id}/cancel`);
}
