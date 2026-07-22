import { api } from "@/lib/api";

// ─── Types ───────────────────────────────────────────────────────────────────

export const REGULATORY_REGIMES = [
  "GDPR_ART33",
  "GDPR_ART34",
  "HIPAA_BREACH",
  "SEC_CYBER",
  "NIS2_EARLY_WARNING",
  "NIS2_NOTIFICATION",
  "NY_DFS_500",
  "UK_GDPR",
  "PIPEDA",
] as const;

export interface StartedClock {
  notification_id: string;
  regime: string;
  deadline_at: string;
}

export interface IncidentNotification {
  notification_id: string;
  regime: string;
  status: string;
  deadline_at: string;
  deadline_hours: number;
  advisory: string;
  submitted: boolean;
}

export interface DeadlineDashboardEntry {
  notification_id: string;
  tenant_id: string;
  regime: string;
  deadline_at: string;
  status: string;
  hours_remaining: number;
}

export interface DraftResult {
  draft_id: string;
  version: number;
}

export interface FinalizeResult {
  status: string;
}

export interface SubmitResult {
  status: string;
  reference: string;
}

// ─── Jurisdictions ───────────────────────────────────────────────────────────

export function configureJurisdictions(jurisdictions: string[]): Promise<{ jurisdictions: string[] }> {
  return api.post<{ jurisdictions: string[] }>("/api/v1/regulatory-notification/jurisdictions", {
    jurisdictions,
  });
}

// ─── Clocks ──────────────────────────────────────────────────────────────────

export function startClocks(incidentId: string, regimes?: string[]): Promise<StartedClock[]> {
  return api.post<StartedClock[]>("/api/v1/regulatory-notification/clocks", {
    incident_id: incidentId,
    regimes,
  });
}

// ─── Drafts ──────────────────────────────────────────────────────────────────

export function createDraft(
  notificationId: string,
  content: string,
  actor: string
): Promise<DraftResult> {
  return api.post<DraftResult>(`/api/v1/regulatory-notification/${notificationId}/drafts`, {
    content,
    actor,
  });
}

export function reviseDraft(
  notificationId: string,
  content: string,
  actor: string
): Promise<DraftResult> {
  return api.post<DraftResult>(`/api/v1/regulatory-notification/${notificationId}/drafts/revise`, {
    content,
    actor,
  });
}

export function finalizeDraft(notificationId: string, actor: string): Promise<FinalizeResult> {
  return api.post<FinalizeResult>(`/api/v1/regulatory-notification/${notificationId}/drafts/finalize`, {
    content: "",
    actor,
  });
}

// ─── Submission ──────────────────────────────────────────────────────────────

export function submitNotification(
  notificationId: string,
  actor: string,
  submissionMethod: string,
  referenceNumber: string
): Promise<SubmitResult> {
  return api.post<SubmitResult>(`/api/v1/regulatory-notification/${notificationId}/submit`, {
    actor,
    submission_method: submissionMethod,
    reference_number: referenceNumber,
  });
}

// ─── Lookups ─────────────────────────────────────────────────────────────────

export function listForIncident(incidentId: string): Promise<IncidentNotification[]> {
  return api.get<IncidentNotification[]>(`/api/v1/regulatory-notification/incident/${incidentId}`);
}

export function getDeadlineDashboard(): Promise<DeadlineDashboardEntry[]> {
  return api.get<DeadlineDashboardEntry[]>("/api/v1/regulatory-notification/deadlines/dashboard");
}

// ─── Admin ───────────────────────────────────────────────────────────────────

export function triggerDeadlineTick(): Promise<Record<string, unknown>> {
  return api.post<Record<string, unknown>>("/api/v1/regulatory-notification/admin/deadline-tick", {});
}

export function getRegulatoryHealth(): Promise<{ status: string; dead_letter_count: number }> {
  return api.get("/api/v1/regulatory-notification/health");
}
