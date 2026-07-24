from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from posture_forecasting.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class GeneratePostureForecast:
    tenant_id: TenantId
    baseline_exposure_score: float
    remediation_velocity_per_day: float
    open_critical_count: int
    open_high_count: int
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RecordForecastAccuracy:
    tenant_id: TenantId
    forecast_id: UUID
    horizon_days: int
    actual_score: float
    roles: tuple[str, ...]
