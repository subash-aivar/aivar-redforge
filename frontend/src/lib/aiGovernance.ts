import { api } from "@/lib/api";

export interface AgentPolicy {
  policy_id: string;
  tenant_id: string;
  name: string;
  description: string;
  status: string;
  rules: PolicyRule[];
  created_at: string;
  updated_at: string;
}

export interface PolicyRule {
  rule_id: string;
  rule_type: string;
  action: string;
  condition: string;
  severity: string;
}

export interface GovernanceViolation {
  violation_id: string;
  policy_id: string;
  agent_id: string;
  rule_id: string;
  severity: string;
  description: string;
  detected_at: string;
  status: string;
}

export interface AgentRegistration {
  agent_id: string;
  tenant_id: string;
  name: string;
  agent_type: string;
  status: string;
  capabilities: string[];
  policies: string[];
  registered_at: string;
}

export function listPolicies(): Promise<AgentPolicy[]> {
  return api.get<AgentPolicy[]>("/api/v1/ai-agent-governance/policies");
}

export function getPolicy(id: string): Promise<AgentPolicy> {
  return api.get<AgentPolicy>(`/api/v1/ai-agent-governance/policies/${id}`);
}

export function listViolations(): Promise<GovernanceViolation[]> {
  return api.get<GovernanceViolation[]>("/api/v1/ai-agent-governance/violations");
}

export function listAgents(): Promise<AgentRegistration[]> {
  return api.get<AgentRegistration[]>("/api/v1/ai-agent-governance/agents");
}

export function registerAgent(body: {
  name: string;
  agent_type: string;
  capabilities: string[];
}): Promise<AgentRegistration> {
  return api.post<AgentRegistration>("/api/v1/ai-agent-governance/agents", body);
}
