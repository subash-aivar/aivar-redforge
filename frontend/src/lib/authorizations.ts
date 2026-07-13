/**
 * Security Authorization & Execution Policy API client — M10.
 *
 * organization_id/requester_user_id are never sent by the client — the
 * backend always derives them from the caller's verified token. There
 * is no client function for setting status directly; every lifecycle
 * transition is its own explicit endpoint, matching the backend's
 * fixed lifecycle graph.
 */
import { api } from "./api";

export interface ScopeEntry {
  entity_type: string;
  entity_id: string;
}

export interface Approval {
  id: string;
  authorization_id: string;
  requester_user_id: string;
  approver_user_id: string | null;
  decision: string | null;
  requested_at: string;
  decided_at: string | null;
  reason: string;
}

export interface Authorization {
  id: string;
  organization_id: string;
  requester_user_id: string;
  status: string;
  action_classes: string[];
  scope: ScopeEntry[];
  valid_from: string;
  valid_until: string;
  created_at: string;
  updated_at: string;
  approval: Approval | null;
}

export interface AuthorizationSummary {
  draft: number;
  pending_approval: number;
  active: number;
  rejected: number;
  revoked: number;
  expired: number;
}

export interface DecisionHistoryEntry {
  id: string;
  authorization_id: string | null;
  actor_user_id: string;
  action_class: string | null;
  raw_action_class: string;
  entity_refs: ScopeEntry[];
  decision: string;
  reason_code: string;
  evaluated_at: string;
}

export interface ListAuthorizationsParams {
  status?: string;
  limit?: number;
  offset?: number;
}

export interface CreateAuthorizationInput {
  action_classes: string[];
  scope: ScopeEntry[];
  valid_from: string;
  valid_until: string;
}

export interface EvaluateInput {
  action_class: string;
  entities: ScopeEntry[];
}

export interface EvaluateResult {
  decision: string;
  reason_code: string;
  decision_id: string;
}

export async function getAuthorizationSummary(): Promise<AuthorizationSummary> {
  return api.get<AuthorizationSummary>("/api/v1/authorizations/summary");
}

export async function listAuthorizations(
  params: ListAuthorizationsParams = {}
): Promise<Authorization[]> {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") query.set(key, String(value));
  }
  const qs = query.toString();
  return api.get<Authorization[]>(`/api/v1/authorizations${qs ? `?${qs}` : ""}`);
}

export async function getAuthorization(id: string): Promise<Authorization> {
  return api.get<Authorization>(`/api/v1/authorizations/${id}`);
}

export async function createAuthorization(
  input: CreateAuthorizationInput
): Promise<Authorization> {
  return api.post<Authorization>("/api/v1/authorizations", input);
}

export async function submitAuthorization(id: string): Promise<Authorization> {
  return api.post<Authorization>(`/api/v1/authorizations/${id}/submit`);
}

export async function approveAuthorization(id: string): Promise<Authorization> {
  return api.post<Authorization>(`/api/v1/authorizations/${id}/approve`);
}

export async function rejectAuthorization(
  id: string,
  reason?: string
): Promise<Authorization> {
  return api.post<Authorization>(`/api/v1/authorizations/${id}/reject`, { reason });
}

export async function revokeAuthorization(
  id: string,
  reason?: string
): Promise<Authorization> {
  return api.post<Authorization>(`/api/v1/authorizations/${id}/revoke`, { reason });
}

export async function evaluatePolicy(input: EvaluateInput): Promise<EvaluateResult> {
  return api.post<EvaluateResult>("/api/v1/authorizations/evaluate", input);
}

export async function listDecisions(
  params: { limit?: number; offset?: number } = {}
): Promise<DecisionHistoryEntry[]> {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) query.set(key, String(value));
  }
  const qs = query.toString();
  return api.get<DecisionHistoryEntry[]>(
    `/api/v1/authorizations/decisions${qs ? `?${qs}` : ""}`
  );
}
