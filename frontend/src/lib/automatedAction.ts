import { api } from "@/lib/api";

// Verified against `backend/src/automated_action/api/v1/routes.py` (router
// has NO path prefix — real paths are `/api/v1/executions...`, not
// `/api/v1/automated-action/...`) and
// `backend/src/automated_action/application/dtos/automation_dtos.py`
// (`AutomationExecutionDTO`/`AutomatedActionRecordDTO` — the real field
// sets, not the previously-fabricated `source_context`/`steps`/etc.).

export interface AutomationExecution {
  execution_id: string;
  tenant_id: string;
  playbook_id: string;
  status: string;
  current_step: number;
  total_steps: number;
  operator_id: string;
  failure_reason: string | null;
}

export interface AutomatedActionRecord {
  record_id: string;
  execution_id: string;
  step_number: number;
  action_type: string;
  connector_type: string;
  status: string;
  outcome: string | null;
  failure_mode: string | null;
}

export function listExecutions(): Promise<AutomationExecution[]> {
  return api.get<AutomationExecution[]>("/api/v1/executions");
}

export function getExecution(executionId: string): Promise<AutomationExecution> {
  return api.get<AutomationExecution>(`/api/v1/executions/${executionId}`);
}

export function listActionRecords(executionId: string): Promise<AutomatedActionRecord[]> {
  return api.get<AutomatedActionRecord[]>(`/api/v1/executions/${executionId}/action-records`);
}

export function triggerExecution(body: {
  playbook_id: string;
  version_number: number;
  source_event_id: string;
  source_context?: string;
  source_event_type?: string;
  operator_id?: string;
}): Promise<AutomationExecution> {
  return api.post<AutomationExecution>("/api/v1/executions", body);
}

export function cancelExecution(executionId: string, reason = "cancelled"): Promise<AutomationExecution> {
  return api.post<AutomationExecution>(`/api/v1/executions/${executionId}/cancel`, {
    cancelled_by: "ui",
    reason,
  });
}

export function authorizeEscalation(
  executionId: string,
  escalationId: string,
  notes?: string
): Promise<AutomationExecution> {
  return api.post<AutomationExecution>(`/api/v1/executions/${executionId}/authorize-step`, {
    escalation_id: escalationId,
    authorizer_id: "ui",
    notes,
  });
}

export function requestRollback(executionId: string, recordId: string): Promise<unknown> {
  return api.post(`/api/v1/executions/${executionId}/rollback`, {
    record_id: recordId,
    initiated_by: "ui",
  });
}
