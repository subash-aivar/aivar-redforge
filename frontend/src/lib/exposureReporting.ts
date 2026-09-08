import { api } from "@/lib/api";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ExposureReportDTO {
  report_id: string;
  tenant_id: string;
  report_type: string;
  status: string;
  template_id: string;
  narrative: string;
  content: Record<string, unknown>;
  generated_by: string;
  generated_at: string;
  time_range_start: string | null;
  time_range_end: string | null;
  delivered_at: string | null;
  data_freshness_warning: boolean;
}

export interface BusinessImpactMappingDTO {
  asset_ref_id: string;
  tenant_id: string;
  criticality: string;
  impact_domain: string;
  authored_by: string;
  business_process_ref: string | null;
  business_unit_ref: string | null;
  financial_impact_estimate: number | null;
  regulatory_scope: string[];
  created_at: string;
  updated_at: string;
}

export interface ExposureReportingDashboard {
  tenant_id: string;
  tenant_exposure_score: number;
  asset_count: number;
  mapped_asset_count: number;
  unmapped_asset_count: number;
  dominant_amplifier: string | null;
  kpi: Record<string, number | string | null>;
  top_assets: Array<{ asset_ref_id: string; score: number }>;
  business_impact_mapped: boolean;
  data_freshness_warning: boolean;
  generated_at: string;
}

export interface ExposureReportingTrend {
  tenant_id: string;
  points: Array<{ computed_at: string; tenant_exposure_score: number; asset_count: number }>;
  score_input_version: number;
}

// ─── Reports ─────────────────────────────────────────────────────────────────

export function generateReport(body: {
  report_type: string;
  generated_by: string;
  time_range_start?: string;
  time_range_end?: string;
}): Promise<ExposureReportDTO> {
  return api.post<ExposureReportDTO>("/api/v1/exposure-reporting/reports", body);
}

export function getReport(reportId: string): Promise<ExposureReportDTO> {
  return api.get<ExposureReportDTO>(`/api/v1/exposure-reporting/reports/${reportId}`);
}

export function listReports(params?: {
  report_type?: string;
  from?: string;
  to?: string;
}): Promise<ExposureReportDTO[]> {
  const q = new URLSearchParams();
  if (params?.report_type) q.set("report_type", params.report_type);
  if (params?.from) q.set("from", params.from);
  if (params?.to) q.set("to", params.to);
  const qs = q.toString();
  return api.get<ExposureReportDTO[]>(`/api/v1/exposure-reporting/reports${qs ? `?${qs}` : ""}`);
}

export function deliverReport(
  reportId: string,
  deliveryChannel: string = "api"
): Promise<ExposureReportDTO> {
  return api.post<ExposureReportDTO>(`/api/v1/exposure-reporting/reports/${reportId}/deliver`, {
    delivery_channel: deliveryChannel,
  });
}

export async function exportReport(
  reportId: string,
  format: "json" | "markdown" = "json"
): Promise<string> {
  const { getApiBase, getAuthHeader } = await import("@/lib/api");
  const res = await fetch(
    `${getApiBase()}/api/v1/exposure-reporting/reports/${reportId}/export?format=${format}`,
    { headers: getAuthHeader() }
  );
  if (!res.ok) throw new Error(`Export failed: ${res.status}`);
  return res.text();
}

// ─── Business Impact Mappings ────────────────────────────────────────────────

export function createBusinessImpactMapping(body: {
  asset_ref_id: string;
  criticality: string;
  impact_domain: string;
  authored_by: string;
  business_process_ref?: string;
  business_unit_ref?: string;
  financial_impact_estimate?: number;
  regulatory_scope?: string[];
}): Promise<BusinessImpactMappingDTO> {
  return api.post<BusinessImpactMappingDTO>(
    "/api/v1/exposure-reporting/business-impact-mappings",
    body
  );
}

export function updateBusinessImpactMapping(
  assetRefId: string,
  body: {
    criticality?: string;
    impact_domain?: string;
    business_process_ref?: string;
    business_unit_ref?: string;
    financial_impact_estimate?: number;
    regulatory_scope?: string[];
  }
): Promise<BusinessImpactMappingDTO> {
  return api.put<BusinessImpactMappingDTO>(
    `/api/v1/exposure-reporting/business-impact-mappings/assets/${assetRefId}`,
    body
  );
}

export function getBusinessImpactMapping(assetRefId: string): Promise<BusinessImpactMappingDTO> {
  return api.get<BusinessImpactMappingDTO>(
    `/api/v1/exposure-reporting/business-impact-mappings/assets/${assetRefId}`
  );
}

export function listBusinessImpactMappings(): Promise<BusinessImpactMappingDTO[]> {
  return api.get<BusinessImpactMappingDTO[]>(
    "/api/v1/exposure-reporting/business-impact-mappings"
  );
}

// ─── Dashboard / Trends / KPIs ───────────────────────────────────────────────

export function getExposureReportingDashboard(): Promise<ExposureReportingDashboard> {
  return api.get<ExposureReportingDashboard>("/api/v1/exposure-reporting/dashboard");
}

export function getExposureReportingTrends(): Promise<ExposureReportingTrend> {
  return api.get<ExposureReportingTrend>("/api/v1/exposure-reporting/trends");
}

export function getExposureReportingKpis(): Promise<Record<string, number>> {
  return api.get<Record<string, number>>("/api/v1/exposure-reporting/kpis");
}
