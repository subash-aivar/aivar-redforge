import { api } from "@/lib/api";

export interface AnalyticsSummaryKpi {
  kpi_type: string;
  status: string;
  latest_value: number | null;
}

export interface AnalyticsSummary {
  tenant_id: string;
  kpis: AnalyticsSummaryKpi[];
  anomaly_count: number;
  datasets: number;
}

export interface AnalyticsAnomaly {
  signal_type: string;
  severity: string;
  score: number;
  observed: number;
  method: string;
  detected_at: string;
}

export function getSummary(): Promise<AnalyticsSummary> {
  return api.get<AnalyticsSummary>("/api/v1/analytics/summary");
}

export function listAnomalies(): Promise<AnalyticsAnomaly[]> {
  return api.get<AnalyticsAnomaly[]>("/api/v1/analytics/anomalies");
}

export function severityTone(
  severity: string
): "critical" | "high" | "warning" | "ok" | "neutral" {
  switch (severity.toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
    case "warning":
      return "warning";
    default:
      return "neutral";
  }
}
