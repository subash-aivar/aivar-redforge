/**
 * AI Agent Governance API client — `ai_agent_governance` bounded context.
 *
 * REPOSITORY AUDIT FINDING (Slice 5): the previous version of this
 * file was entirely fictional — `/policies`, `/violations`, `/agents`
 * do not exist anywhere in the backend. The real routes are
 * `/envelopes` (draft), `/envelopes/{id}/actions`,
 * `/envelopes/{id}/approve`, `/envelopes/{id}/revise`,
 * `/envelopes/{id}/suspend`, `/actions/report`,
 * `/deviations/{id}/review`, `/envelopes/{id}/advisories` — verified
 * against `backend/src/ai_agent_governance/api/v1/routes.py` and the
 * real `EnvelopeDTO`/`DeviationDTO`/`AdvisoryDTO` dataclasses.
 *
 * This context is entirely command-based — there is NO list/get
 * endpoint for envelopes at all, only `advisories` (by envelope ID).
 * This is a real backend gap, not a frontend oversight: an operator
 * cannot discover envelope IDs from this API. This client exposes
 * exactly what's real; the page built on it is honest about that gap
 * rather than fabricating a list.
 */
import { api } from "@/lib/api";

export interface Envelope {
  envelope_id: string;
  tenant_id: string;
  ai_system_asset_id: string;
  state: string;
  envelope_version: number;
  action_categories: string[];
  requires_human_approval_for: string[];
  approved_by: string | null;
}

export interface Deviation {
  deviation_id: string;
  tenant_id: string;
  ai_system_asset_id: string;
  deviation_type: string;
  severity: string;
  review_state: string;
  envelope_version: number;
  review_notes: string;
}

export interface ReportActionResult {
  status: "compliant" | "deviation" | "duplicate";
  deviation: Deviation | null;
}

export interface Advisory {
  envelope_id: string;
  deviation_type: string;
  confirmed_benign_count: number;
  recommendation: string;
}

export function draftEnvelope(body: {
  asset_id: string;
  max_data_sensitivity?: string;
  requires_human_approval_for?: string[];
}): Promise<Envelope> {
  return api.post<Envelope>("/api/v1/ai-agent-governance/envelopes", body);
}

export function addAction(envelopeId: string, category: string, description = ""): Promise<Envelope> {
  return api.post<Envelope>(`/api/v1/ai-agent-governance/envelopes/${envelopeId}/actions`, {
    category,
    description,
  });
}

export function approveEnvelope(envelopeId: string, approverId: string): Promise<Envelope> {
  return api.post<Envelope>(`/api/v1/ai-agent-governance/envelopes/${envelopeId}/approve`, {
    approver_id: approverId,
  });
}

export function suspendEnvelope(envelopeId: string, reason: string): Promise<Envelope> {
  return api.post<Envelope>(`/api/v1/ai-agent-governance/envelopes/${envelopeId}/suspend`, { reason });
}

export function reviewDeviation(
  deviationId: string,
  decision: string,
  notes = ""
): Promise<Deviation> {
  return api.post<Deviation>(`/api/v1/ai-agent-governance/deviations/${deviationId}/review`, {
    decision,
    notes,
  });
}

export function getAdvisories(envelopeId: string): Promise<Advisory[]> {
  return api.get<Advisory[]>(`/api/v1/ai-agent-governance/envelopes/${envelopeId}/advisories`);
}
