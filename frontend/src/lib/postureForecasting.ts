import { api } from "@/lib/api";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface PostureForecastDTO {
  forecast_id: string;
  tenant_id: string;
  predicted_30d: number;
  predicted_60d: number;
  predicted_90d: number;
  baseline_exposure_score: number;
  generated_at: string;
}

// ─── API ─────────────────────────────────────────────────────────────────────

export function generateForecast(body: {
  baseline_exposure_score: number;
  remediation_velocity_per_day?: number;
  open_critical_count?: number;
  open_high_count?: number;
}): Promise<PostureForecastDTO> {
  return api.post<PostureForecastDTO>("/api/v1/posture-forecasting/forecasts", body);
}

export function getLatestForecast(): Promise<PostureForecastDTO> {
  return api.get<PostureForecastDTO>("/api/v1/posture-forecasting/forecasts/latest");
}
