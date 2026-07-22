from __future__ import annotations

from posture_forecasting.domain.aggregates.posture_forecast import PostureForecast


class ForecastAccuracyService:
    def record(self, forecast: PostureForecast, horizon_days: int, actual_score: float) -> None:
        predicted = {
            30: forecast.predicted_30d,
            60: forecast.predicted_60d,
            90: forecast.predicted_90d,
        }[horizon_days]
        forecast.record_accuracy(horizon_days, actual_score, predicted)
