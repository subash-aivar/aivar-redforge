from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PostureForecastDTO:
    forecast_id: str
    tenant_id: str
    predicted_30d: float
    predicted_60d: float
    predicted_90d: float
    baseline_exposure_score: float
    generated_at: str
