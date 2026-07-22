from __future__ import annotations

from dataclasses import dataclass, field

from posture_forecasting.domain.value_objects.identifiers import TenantId


@dataclass
class ForecastConfiguration:
    tenant_id: TenantId
    forecast_frequency_hours: int = 24
    signal_weights: dict[str, float] = field(
        default_factory=lambda: {"exposure": 0.6, "remediation_velocity": 0.4}
    )

    @classmethod
    def default(cls, tenant_id: TenantId) -> ForecastConfiguration:
        return cls(tenant_id)
