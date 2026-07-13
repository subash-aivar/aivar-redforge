/**
 * Continuous Validation Scheduler, Security Drift Detection &
 * Revalidation Engine API client — M14.
 *
 * organization_id/requester_user_id are never sent by the client — the
 * backend always derives them from the caller's verified token.
 * Cadence is one of a closed set of server-controlled strings
 * ("hourly" | "every_6_hours" | "daily" | "weekly") — there is no free
 * text field and no cron expression anywhere in this client.
 */
import { api } from "./api";

export type PolicyLifecycle = "draft" | "active" | "paused" | "disabled";
export type ValidationCadence = "hourly" | "every_6_hours" | "daily" | "weekly";

export interface ContinuousValidationPolicy {
  id: string;
  organization_id: string;
  target_id: string;
  requester_user_id: string;
  profile: string;
  cadence: ValidationCadence;
  lifecycle: PolicyLifecycle;
  next_due_at: string | null;
  last_scheduled_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface SecurityDriftEvent {
  id: string;
  organization_id: string;
  continuous_policy_id: string;
  execution_id: string;
  category: string;
  identity_key: string;
  summary: string;
  detail: Record<string, string>;
  detected_at: string;
}

export interface RunNowResult {
  execution_id: string;
  status: string;
  trigger: string;
}

export interface CreatePolicyInput {
  target_id: string;
  profile?: string;
  cadence?: ValidationCadence;
}

export interface ListPoliciesParams {
  lifecycle?: PolicyLifecycle;
  limit?: number;
  offset?: number;
}

export interface ListDriftParams {
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

export async function createPolicy(
  input: CreatePolicyInput
): Promise<ContinuousValidationPolicy> {
  return api.post<ContinuousValidationPolicy>("/api/v1/continuous-validation/policies", input);
}

export async function listPolicies(
  params: ListPoliciesParams = {}
): Promise<ContinuousValidationPolicy[]> {
  return api.get<ContinuousValidationPolicy[]>(
    `/api/v1/continuous-validation/policies${toQueryString(params)}`
  );
}

export async function getPolicy(id: string): Promise<ContinuousValidationPolicy> {
  return api.get<ContinuousValidationPolicy>(`/api/v1/continuous-validation/policies/${id}`);
}

export async function activatePolicy(id: string): Promise<ContinuousValidationPolicy> {
  return api.post<ContinuousValidationPolicy>(
    `/api/v1/continuous-validation/policies/${id}/activate`
  );
}

export async function pausePolicy(id: string): Promise<ContinuousValidationPolicy> {
  return api.post<ContinuousValidationPolicy>(
    `/api/v1/continuous-validation/policies/${id}/pause`
  );
}

export async function resumePolicy(id: string): Promise<ContinuousValidationPolicy> {
  return api.post<ContinuousValidationPolicy>(
    `/api/v1/continuous-validation/policies/${id}/resume`
  );
}

export async function disablePolicy(id: string): Promise<ContinuousValidationPolicy> {
  return api.post<ContinuousValidationPolicy>(
    `/api/v1/continuous-validation/policies/${id}/disable`
  );
}

export async function runPolicyNow(id: string): Promise<RunNowResult> {
  return api.post<RunNowResult>(`/api/v1/continuous-validation/policies/${id}/run-now`);
}

export async function listPolicyDrift(
  id: string,
  params: ListDriftParams = {}
): Promise<SecurityDriftEvent[]> {
  return api.get<SecurityDriftEvent[]>(
    `/api/v1/continuous-validation/policies/${id}/drift${toQueryString(params)}`
  );
}

export async function getDriftDetail(id: string): Promise<SecurityDriftEvent> {
  return api.get<SecurityDriftEvent>(`/api/v1/continuous-validation/drift/${id}`);
}

export async function getChangeFeed(
  params: ListDriftParams = {}
): Promise<SecurityDriftEvent[]> {
  return api.get<SecurityDriftEvent[]>(
    `/api/v1/continuous-validation/change-feed${toQueryString(params)}`
  );
}
