from __future__ import annotations

from posture_forecasting.domain.aggregates.posture_forecast import PostureForecast
from posture_forecasting.domain.value_objects.identifiers import TenantId
from posture_forecasting.domain.value_objects.snapshots import ForecastInputSnapshot


class ForecastGenerationService:
    def generate(self, tenant_id: TenantId, snapshot: ForecastInputSnapshot) -> PostureForecast:
        # simple linear trajectory using remediation velocity
        decay = max(0.0, snapshot.remediation_velocity_per_day * 0.01)
        p30 = max(0.0, snapshot.baseline_exposure_score - decay * 30)
        p60 = max(0.0, snapshot.baseline_exposure_score - decay * 60)
        p90 = max(0.0, snapshot.baseline_exposure_score - decay * 90)
        return PostureForecast.create(tenant_id, snapshot, p30, p60, p90, "forecast-v1", 1)
