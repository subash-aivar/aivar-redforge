from __future__ import annotations

from typing import Any
from uuid import UUID

from posture_forecasting.application.commands.forecast_commands import GeneratePostureForecast


class PostureForecastWorker:
    def __init__(self, app: Any) -> None:
        self._app = app
        self.runs = 0

    async def tick(
        self,
        tenant_id: UUID,
        baseline: float = 50.0,
        velocity: float = 1.0,
        critical: int = 2,
        high: int = 5,
    ) -> Any:
        self.runs += 1
        return await self._app.generate(
            GeneratePostureForecast(tenant_id, baseline, velocity, critical, high, ("system",))
        )


class ForecastAccuracyWorker:
    def __init__(self, forecasts: Any, accuracy_service: Any) -> None:
        self._forecasts = forecasts
        self._accuracy = accuracy_service
        self.runs = 0

    async def tick(self, tenant_id: UUID, actual_score: float = 40.0) -> int:
        from datetime import UTC, datetime

        from posture_forecasting.domain.value_objects.identifiers import TenantId

        self.runs += 1
        count = 0
        for horizon in (30, 60, 90):
            pending = await self._forecasts.find_pending_accuracy_check(horizon, datetime.now(UTC))
            for forecast in pending:
                if str(forecast.tenant_id) != str(tenant_id):
                    continue
                self._accuracy.record(forecast, horizon, actual_score)
                await self._forecasts.save(forecast, TenantId(tenant_id))
                count += 1
        return count


class ForecastScheduler:
    def __init__(
        self, forecast_worker: PostureForecastWorker, accuracy_worker: ForecastAccuracyWorker
    ) -> None:
        self.forecast_worker = forecast_worker
        self.accuracy_worker = accuracy_worker

    async def tick_all(self, tenant_id: UUID) -> dict[str, int]:
        await self.forecast_worker.tick(tenant_id)
        measured = await self.accuracy_worker.tick(tenant_id)
        return {"forecast_runs": self.forecast_worker.runs, "accuracy_updates": measured}
