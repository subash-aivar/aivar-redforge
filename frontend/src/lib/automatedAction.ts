import { api } from "@/lib/api";

export interface AutomationExecution {
  execution_id: string;
  playbook_id: string;
  tenant_id: string;
  status: string;
  source_context: string;
  source_event_type: string;
  created_at: string;
  completed_at: string | null;
  steps: AutomationStep[];
}

export interface AutomationStep {
  step_id: string;
  step_type: string;
  status: string;
  result: Record<string, unknown> | null;
  error: string | null;
}

export interface Escalation {
  escalation_id: string;
  execution_id: string;
  step_id: string;
  status: string;
  requested_at: string;
}

export function listExecutions(): Promise<AutomationExecution[]> {
  return api.get<AutomationExecution[]>("/api/v1/automated-action/executions");
}

export function getExecution(executionId: string): Promise<AutomationExecution> {
  return api.get<AutomationExecution>(`/api/v1/automated-action/executions/${executionId}`);
}

export function triggerExecution(body: {
  playbook_id: string;
  version_number: number;
  source_event_id: string;
  source_context?: string;
}): Promise<AutomationExecution> {
  return api.post<AutomationExecution>("/api/v1/automated-action/trigger", body);
}

export function cancelExecution(executionId: string, reason = "cancelled"): Promise<AutomationExecution> {
  return api.post<AutomationExecution>(`/api/v1/automated-action/executions/${executionId}/cancel`, {
    cancelled_by: "ui",
    reason,
  });
}

export function authorizeEscalation(escalationId: string, notes?: string): Promise<void> {
  return api.post("/api/v1/automated-action/authorize", {
    escalation_id: escalationId,
    authorizer_id: "ui",
    notes,
  });
}

export function requestRollback(recordId: string): Promise<void> {
  return api.post("/api/v1/automated-action/rollback", {
    record_id: recordId,
    initiated_by: "ui",
  });
}
