import { api } from "@/lib/api";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ReportInstanceDTO {
  instance_id: string;
  tenant_id: string;
  template_id: string;
  report_type: string;
  status: string;
  trigger: string;
  narrative: string;
  narrative_variant: string;
  content: Record<string, unknown>;
  artifact_ref: string | null;
  error_reason: string | null;
  generated_by: string;
  created_at: string;
  completed_at: string | null;
  schedule_id: string | null;
}

export interface ScheduledReportDTO {
  schedule_id: string;
  tenant_id: string;
  template_id: string;
  schedule: string;
  cadence_minutes: number;
  status: string;
  next_run_at: string;
  last_run_at: string | null;
  parameters: Record<string, unknown>;
  recipients: string[];
  created_by: string;
  created_at: string;
}

export interface ReportTemplate {
  template_id: string;
  report_type: string;
  name: string;
  sections: string[];
}

export interface ExportReportResult {
  content_base64: string;
  format: string;
  [key: string]: unknown;
}

export interface BiExportResult {
  items: Array<Record<string, unknown>>;
  page: number;
  page_size: number;
  total: number;
  [key: string]: unknown;
}

// ─── Templates ───────────────────────────────────────────────────────────────

export function listTemplates(): Promise<ReportTemplate[]> {
  return api.get<ReportTemplate[]>("/api/v1/reporting/templates");
}

// ─── Scheduled Reports ───────────────────────────────────────────────────────

export function createScheduledReport(body: {
  template_id: string;
  schedule?: string;
  parameters?: Record<string, unknown>;
  recipients?: string[];
  cadence_minutes?: number;
  created_by?: string;
}): Promise<ScheduledReportDTO> {
  return api.post<ScheduledReportDTO>("/api/v1/reporting/schedules", body);
}

// ─── On-Demand Reports ───────────────────────────────────────────────────────

export function generateReportOnDemand(body: {
  template_id: string;
  parameters?: Record<string, unknown>;
  generated_by?: string;
}): Promise<ReportInstanceDTO> {
  return api.post<ReportInstanceDTO>("/api/v1/reporting/reports", body);
}

export function getReportInstance(instanceId: string): Promise<ReportInstanceDTO> {
  return api.get<ReportInstanceDTO>(`/api/v1/reporting/reports/${instanceId}`);
}

export function listReportInstances(params?: {
  template_id?: string;
  from?: string;
  to?: string;
}): Promise<ReportInstanceDTO[]> {
  const q = new URLSearchParams();
  if (params?.template_id) q.set("template_id", params.template_id);
  if (params?.from) q.set("from", params.from);
  if (params?.to) q.set("to", params.to);
  const qs = q.toString();
  return api.get<ReportInstanceDTO[]>(`/api/v1/reporting/reports${qs ? `?${qs}` : ""}`);
}

export function exportReportInstance(
  instanceId: string,
  format: string = "CSV"
): Promise<ExportReportResult> {
  return api.post<ExportReportResult>(`/api/v1/reporting/reports/${instanceId}/export`, {
    format,
  });
}

export async function downloadExportedReport(
  instanceId: string,
  format: string = "CSV"
): Promise<void> {
  const result = await exportReportInstance(instanceId, format);
  const binary = atob(result.content_base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  const blob = new Blob([bytes]);
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${instanceId}.${format.toLowerCase()}`;
  a.click();
  URL.revokeObjectURL(url);
}

// ─── BI Export ───────────────────────────────────────────────────────────────

export function biExport(body: {
  dataset_ref: string;
  page?: number;
  page_size?: number;
  actor?: string;
}): Promise<BiExportResult> {
  return api.post<BiExportResult>("/api/v1/reporting/bi-export", body);
}

// ─── Delivery Audit ──────────────────────────────────────────────────────────

export function listDeliveryAudit(): Promise<Array<Record<string, unknown>>> {
  return api.get<Array<Record<string, unknown>>>("/api/v1/reporting/delivery-audit");
}

// ─── Health ──────────────────────────────────────────────────────────────────

export function getReportingHealth(): Promise<{ status: string; template_count: number; delivery_audit_count: number }> {
  return api.get("/api/v1/reporting/health");
}
