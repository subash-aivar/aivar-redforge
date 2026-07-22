from __future__ import annotations

from datetime import datetime, timedelta

from posture_forecasting.domain.aggregates.forecast_configuration import ForecastConfiguration
from posture_forecasting.domain.aggregates.posture_forecast import PostureForecast
from posture_forecasting.domain.repositories.i_repositories import (
    IForecastConfigurationRepository,
    IPostureForecastRepository,
)
from posture_forecasting.domain.value_objects.identifiers import TenantId


class InMemoryPostureForecastRepository(IPostureForecastRepository):
    def __init__(self) -> None:
        self._items: dict[str, list[PostureForecast]] = {}

    async def save(self, forecast: PostureForecast, tenant_id: TenantId) -> None:
        self._items.setdefault(str(tenant_id), []).append(forecast)

    async def find_latest(self, tenant_id: TenantId) -> PostureForecast | None:
        rows = self._items.get(str(tenant_id), [])
        if not rows:
            return None
        return max(rows, key=lambda f: f.generated_at)

    async def find_pending_accuracy_check(
        self, horizon_days: int, cutoff: datetime
    ) -> list[PostureForecast]:
        out: list[PostureForecast] = []
        for rows in self._items.values():
            for f in rows:
                if f.generated_at <= cutoff - timedelta(days=horizon_days) and not any(
                    r.horizon_days == horizon_days for r in f.accuracy_records
                ):
                    out.append(f)
        return out


class InMemoryForecastConfigurationRepository(IForecastConfigurationRepository):
    def __init__(self) -> None:
        self._items: dict[str, ForecastConfiguration] = {}

    async def get_or_create_default(self, tenant_id: TenantId) -> ForecastConfiguration:
        key = str(tenant_id)
        if key not in self._items:
            self._items[key] = ForecastConfiguration.default(tenant_id)
        return self._items[key]
