/**
 * Security Condition API client — M8.
 *
 * Read-only plus explicit `resolve` only. No client function exists to
 * create a canonical condition, set `evidence_state=validated`, or
 * choose a severity — those are internal-only application boundaries
 * (M6/M7 analyzer integrations), never reachable from the browser.
 */
import { api } from "./api";

export interface EvidenceItem {
  label: string;
  value: string;
  truncated: "true" | "false";
}

export interface SecurityCondition {
  id: string;
  organization_id: string;
  affected_asset_id: string;
  source_category: string;
  stable_rule_id: string;
  evidence_state: string;
  severity: string;
  title: string;
  summary: string;
  remediation: string;
  canonical_references: string[];
  evidence: EvidenceItem[];
  lifecycle: string;
  first_observed_at: string;
  last_observed_at: string;
}

export interface SecurityConditionSummary {
  by_evidence_state: Record<string, number>;
  by_severity: Record<string, number>;
  by_source_category: Record<string, number>;
  by_lifecycle: Record<string, number>;
}

export interface ListSecurityConditionsParams {
  evidence_state?: string;
  severity?: string;
  source_category?: string;
  asset_kind?: string;
  limit?: number;
  offset?: number;
}

export async function getSecurityConditionSummary(): Promise<SecurityConditionSummary> {
  return api.get<SecurityConditionSummary>("/api/v1/security-conditions/summary");
}

export async function listSecurityConditions(
  params: ListSecurityConditionsParams = {}
): Promise<SecurityCondition[]> {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") query.set(key, String(value));
  }
  const qs = query.toString();
  return api.get<SecurityCondition[]>(
    `/api/v1/security-conditions${qs ? `?${qs}` : ""}`
  );
}

export async function getSecurityCondition(id: string): Promise<SecurityCondition> {
  return api.get<SecurityCondition>(`/api/v1/security-conditions/${id}`);
}

export async function resolveSecurityCondition(id: string): Promise<SecurityCondition> {
  return api.post<SecurityCondition>(`/api/v1/security-conditions/${id}/resolve`);
}
