from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from posture_forecasting.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True, kw_only=True)
class ForecastInputSnapshot:
    baseline_exposure_score: float
    remediation_velocity_per_day: float
    open_critical_count: int
    open_high_count: int
    snapshot_at: datetime
    tenant_id: TenantId


@dataclass
class ForecastAccuracyRecord:
    horizon_days: int
    actual_score: float
    predicted_score: float
    absolute_error: float
    recorded_at: datetime
