import { api } from "@/lib/api";

export interface Playbook {
  playbook_id: string;
  tenant_id: string;
  name: string;
  description: string;
  status: string;
  current_version_number: number;
  max_impact_level: string;
  created_by: string;
  approved_by: string[];
}

export interface AutomationPolicy {
  tenant_id: string;
  kill_switch_state: string;
  kill_switch_triggered_by: string | null;
  max_concurrent_executions: number;
  max_actions_per_hour: number;
}

export function listPlaybooks(): Promise<Playbook[]> {
  return api.get<Playbook[]>("/api/v1/playbooks");
}

export function getPlaybook(playbookId: string): Promise<Playbook> {
  return api.get<Playbook>(`/api/v1/playbooks/${playbookId}`);
}

export function approvePlaybook(
  playbookId: string,
  versionNumber: number,
  approvedBy: string,
  approvedByRole: string
): Promise<unknown> {
  return api.post(`/api/v1/playbooks/${playbookId}/approve`, {
    version_number: versionNumber,
    approved_by: approvedBy,
    approved_by_role: approvedByRole,
  });
}

export function getAutomationPolicy(): Promise<AutomationPolicy> {
  return api.get<AutomationPolicy>("/api/v1/automation-policy");
}

export function triggerKillSwitch(
  activatedBy: string,
  reason: string
): Promise<AutomationPolicy> {
  return api.post<AutomationPolicy>("/api/v1/automation-policy/kill-switch", {
    activated_by: activatedBy,
    reason,
  });
}

export function resetKillSwitch(resetBy = "api"): Promise<AutomationPolicy> {
  return api.delete<AutomationPolicy>(
    `/api/v1/automation-policy/kill-switch?reset_by=${encodeURIComponent(resetBy)}`
  );
}

export function statusTone(status: string): "critical" | "high" | "warning" | "ok" | "neutral" {
  switch (status.toUpperCase()) {
    case "ACTIVE":
      return "ok";
    case "PENDING_APPROVAL":
    case "DRAFT":
      return "warning";
    case "DEPRECATED":
      return "neutral";
    default:
      return "neutral";
  }
}
