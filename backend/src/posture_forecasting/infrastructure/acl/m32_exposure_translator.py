from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ExposureScoreUpdatedPayload:
    tenant_id: str
    exposure_score: float
    open_critical_count: int
    open_high_count: int
    remediation_velocity_per_day: float


@dataclass(frozen=True, slots=True)
class ForecastInputSignal:
    tenant_id: str
    exposure_score: float
    open_critical_count: int
    open_high_count: int
    remediation_velocity_per_day: float


class M32ExposureTranslator:
    def translate(self, payload: ExposureScoreUpdatedPayload) -> ForecastInputSignal | None:
        try:
            return ForecastInputSignal(
                payload.tenant_id,
                payload.exposure_score,
                payload.open_critical_count,
                payload.open_high_count,
                payload.remediation_velocity_per_day,
            )
        except Exception:
            return None
