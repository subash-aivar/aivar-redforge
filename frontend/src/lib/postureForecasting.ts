import { api } from "@/lib/api";

export interface PostureForecast {
  forecast_id: string;
  tenant_id: string;
  horizon_days: number;
  predicted_score: number;
  confidence: number;
  risk_drivers: RiskDriver[];
  generated_at: string;
}

export interface RiskDriver {
  driver_type: string;
  contribution: number;
  description: string;
}

export interface TrendPoint {
  date: string;
  score: number;
  actual: boolean;
}

export function getLatestForecast(): Promise<PostureForecast> {
  return api.get<PostureForecast>("/api/v1/posture-forecasting/latest");
}

export function generateForecast(horizonDays = 30): Promise<PostureForecast> {
  return api.post<PostureForecast>("/api/v1/posture-forecasting/generate", {
    horizon_days: horizonDays,
  });
}

export function getTrend(days = 90): Promise<TrendPoint[]> {
  return api.get<TrendPoint[]>(`/api/v1/posture-forecasting/trend?days=${days}`);
}
