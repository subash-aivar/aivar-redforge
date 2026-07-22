from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from posture_forecasting.application._auth import require_any
from posture_forecasting.application.commands.forecast_commands import (
    GeneratePostureForecast,
    RecordForecastAccuracy,
)
from posture_forecasting.application.dtos.forecast_dtos import PostureForecastDTO
from posture_forecasting.application.exceptions import ApplicationNotFoundError
from posture_forecasting.domain.services.forecast_accuracy_service import ForecastAccuracyService
from posture_forecasting.domain.services.forecast_generation_service import (
    ForecastGenerationService,
)
from posture_forecasting.domain.value_objects.identifiers import TenantId
from posture_forecasting.domain.value_objects.snapshots import ForecastInputSnapshot


class ForecastApplicationService:
    def __init__(self, forecasts: Any, configs: Any, event_sink: list[Any] | None = None) -> None:
        self._forecasts = forecasts
        self._configs = configs
        self._events: list[Any] = event_sink if event_sink is not None else []
        self._gen = ForecastGenerationService()
        self._acc = ForecastAccuracyService()

    def _tenant(self, value: UUID) -> TenantId:
        return TenantId(value)

    async def generate(self, cmd: GeneratePostureForecast) -> PostureForecastDTO:
        require_any(cmd.roles, "ai:operator", "system", "vuln:manager")
        tenant = self._tenant(cmd.tenant_id)
        await self._configs.get_or_create_default(tenant)
        snapshot = ForecastInputSnapshot(
            baseline_exposure_score=cmd.baseline_exposure_score,
            remediation_velocity_per_day=cmd.remediation_velocity_per_day,
            open_critical_count=cmd.open_critical_count,
            open_high_count=cmd.open_high_count,
            snapshot_at=datetime.now(UTC),
            tenant_id=tenant,
        )
        forecast = self._gen.generate(tenant, snapshot)
        await self._forecasts.save(forecast, tenant)
        self._events.extend(forecast.pop_events())
        return PostureForecastDTO(
            str(forecast.forecast_id),
            str(tenant),
            forecast.predicted_30d,
            forecast.predicted_60d,
            forecast.predicted_90d,
            snapshot.baseline_exposure_score,
            forecast.generated_at.isoformat(),
        )

    async def record_accuracy(self, cmd: RecordForecastAccuracy) -> PostureForecastDTO:
        require_any(cmd.roles, "ai:operator", "system")
        tenant = self._tenant(cmd.tenant_id)
        forecast = await self._forecasts.find_latest(tenant)
        if forecast is None or forecast.forecast_id.value != cmd.forecast_id:
            # allow lookup by scanning — latest only for simplicity
            raise ApplicationNotFoundError("forecast not found")
        self._acc.record(forecast, cmd.horizon_days, cmd.actual_score)
        await self._forecasts.save(forecast, tenant)
        self._events.extend(forecast.pop_events())
        return PostureForecastDTO(
            str(forecast.forecast_id),
            str(tenant),
            forecast.predicted_30d,
            forecast.predicted_60d,
            forecast.predicted_90d,
            forecast.input_snapshot.baseline_exposure_score,
            forecast.generated_at.isoformat(),
        )

    async def get_latest(self, tenant_id: UUID, roles: tuple[str, ...]) -> PostureForecastDTO:
        require_any(roles, "ai:operator", "vuln:manager", "playbook:analyst")
        forecast = await self._forecasts.find_latest(self._tenant(tenant_id))
        if forecast is None:
            raise ApplicationNotFoundError("forecast not found")
        return PostureForecastDTO(
            str(forecast.forecast_id),
            str(tenant_id),
            forecast.predicted_30d,
            forecast.predicted_60d,
            forecast.predicted_90d,
            forecast.input_snapshot.baseline_exposure_score,
            forecast.generated_at.isoformat(),
        )
