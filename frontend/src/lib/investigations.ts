/**
 * AIVAR RedForge — Cross-Domain Security Investigation API client (M21).
 *
 * All data is derived from canonical investigation cases.
 * No synthetic or fabricated values are introduced.
 *
 * Every case has a deterministic correlation_key linking it to a specific
 * rule and entity set. Confidence is a four-level enum, not an opaque score.
 */

import { api } from "@/lib/api";

// ── Types ─────────────────────────────────────────────────────────────────────

export type InvestigationStatus = "OPEN" | "ACKNOWLEDGED" | "INVESTIGATING" | "RESOLVED";
export type InvestigationSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type CorrelationConfidence = "LOW" | "MEDIUM" | "HIGH" | "VERY_HIGH";

export interface InvolvedEntity {
  type: string;
  id: string;
}

export interface InvestigationCase {
  id: string;
  organization_id: string;
  title: string;
  summary: string;
  status: InvestigationStatus;
  severity: InvestigationSeverity;
  confidence: CorrelationConfidence;
  source_domains: string[];
  involved_entities: InvolvedEntity[];
  evidence_count: number;
  first_observed_at: string;
  last_observed_at: string;
  opened_at: string;
  acknowledged_at: string | null;
  investigating_at: string | null;
  resolved_at: string | null;
  resolution_reason: string | null;
  resolution_notes: string | null;
  version: number;
  created_at: string;
  updated_at: string;
  domain_count?: number;
}

export interface InvestigationPosture {
  open_cases: number;
  acknowledged_cases: number;
  investigating_cases: number;
  resolved_cases: number;
  critical_cases: number;
  high_cases: number;
  multi_domain_cases: number;
  total_active: number;
}

export interface EvidenceLink {
  id: string;
  case_id: string;
  source_domain: string;
  source_entity_type: string;
  source_entity_id: string;
  event_type: string;
  severity: string;
  observed_at: string;
  evidence_snapshot: Record<string, unknown>;
  correlation_reason: string;
  relationship_type: string;
  observability: string;
  dedup_key: string;
  created_at: string;
}

export interface InvestigationTimelineEvent {
  id: string;
  event_id: string;
  case_id: string;
  event_type: string;
  detail: Record<string, unknown>;
  actor_user_id: string | null;
  occurred_at: string;
}

export interface InvestigationGraphNode {
  id: string;
  kind: string;
  label: string;
  severity?: string;
  status?: string;
  source_domain?: string;
}

export interface InvestigationGraphEdge {
  source: string;
  target: string;
  kind: string;
  observability: string;
  reason: string;
}

export interface InvestigationGraph {
  case_id: string;
  nodes: InvestigationGraphNode[];
  edges: InvestigationGraphEdge[];
  ontology_version: number;
}

// ── API Calls ─────────────────────────────────────────────────────────────────

export function getInvestigationPosture(): Promise<InvestigationPosture> {
  return api.get<InvestigationPosture>("/api/v1/investigations/posture");
}

export function listInvestigations(params?: {
  status?: string;
  severity?: string;
  limit?: number;
  offset?: number;
}): Promise<InvestigationCase[]> {
  const q = new URLSearchParams();
  if (params?.status) q.set("status", params.status);
  if (params?.severity) q.set("severity", params.severity);
  if (params?.limit != null) q.set("limit", String(params.limit));
  if (params?.offset != null) q.set("offset", String(params.offset));
  const qs = q.toString();
  return api.get<InvestigationCase[]>(`/api/v1/investigations${qs ? `?${qs}` : ""}`);
}

export function getInvestigation(caseId: string): Promise<InvestigationCase> {
  return api.get<InvestigationCase>(`/api/v1/investigations/${caseId}`);
}

export function getInvestigationTimeline(
  caseId: string,
  limit = 200
): Promise<InvestigationTimelineEvent[]> {
  return api.get<InvestigationTimelineEvent[]>(
    `/api/v1/investigations/${caseId}/timeline?limit=${limit}`
  );
}

export function getInvestigationEvidence(
  caseId: string,
  sourceDomain?: string
): Promise<EvidenceLink[]> {
  const q = sourceDomain ? `?source_domain=${encodeURIComponent(sourceDomain)}` : "";
  return api.get<EvidenceLink[]>(`/api/v1/investigations/${caseId}/evidence${q}`);
}

export function getInvestigationGraph(caseId: string): Promise<InvestigationGraph> {
  return api.get<InvestigationGraph>(`/api/v1/investigations/${caseId}/graph`);
}

export function acknowledgeInvestigation(caseId: string): Promise<{ case_id: string; status: string }> {
  return api.post(`/api/v1/investigations/${caseId}/acknowledge`, {});
}

export function startInvestigation(caseId: string): Promise<{ case_id: string; status: string }> {
  return api.post(`/api/v1/investigations/${caseId}/start-investigation`, {});
}

export function resolveInvestigation(
  caseId: string,
  resolution_reason: string,
  notes: string
): Promise<{ case_id: string; status: string }> {
  return api.post(`/api/v1/investigations/${caseId}/resolve`, { resolution_reason, notes });
}

// ── Display helpers ───────────────────────────────────────────────────────────

export function severityColor(severity: string): string {
  switch (severity) {
    case "CRITICAL": return "border-red-700 bg-red-900/30 text-red-300";
    case "HIGH": return "border-orange-700 bg-orange-900/30 text-orange-300";
    case "MEDIUM": return "border-yellow-700 bg-yellow-900/30 text-yellow-300";
    case "LOW": return "border-gray-600 bg-gray-800 text-gray-300";
    default: return "border-gray-600 bg-gray-800 text-gray-300";
  }
}

export function confidenceColor(confidence: string): string {
  switch (confidence) {
    case "VERY_HIGH": return "border-purple-700 bg-purple-900/30 text-purple-300";
    case "HIGH": return "border-blue-700 bg-blue-900/30 text-blue-300";
    case "MEDIUM": return "border-cyan-700 bg-cyan-900/30 text-cyan-300";
    case "LOW": return "border-gray-600 bg-gray-800 text-gray-400";
    default: return "border-gray-600 bg-gray-800 text-gray-400";
  }
}

export function statusColor(status: string): string {
  switch (status) {
    case "OPEN": return "border-red-700 bg-red-900/20 text-red-300";
    case "ACKNOWLEDGED": return "border-yellow-700 bg-yellow-900/20 text-yellow-300";
    case "INVESTIGATING": return "border-blue-700 bg-blue-900/20 text-blue-300";
    case "RESOLVED": return "border-green-700 bg-green-900/20 text-green-300";
    default: return "border-gray-600 bg-gray-800 text-gray-300";
  }
}

export function domainColor(domain: string): string {
  switch (domain) {
    case "behavior": return "border-purple-700 bg-purple-900/20 text-purple-300";
    case "ddos": return "border-red-700 bg-red-900/20 text-red-300";
    case "threat_intel": return "border-orange-700 bg-orange-900/20 text-orange-300";
    default: return "border-gray-600 bg-gray-800 text-gray-300";
  }
}

export function domainLabel(domain: string): string {
  switch (domain) {
    case "behavior": return "Behavior";
    case "ddos": return "DDoS";
    case "threat_intel": return "Threat Intel";
    default: return domain;
  }
}

export function formatTs(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, {
    year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}
