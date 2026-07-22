from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime

from posture_forecasting.domain.aggregates.forecast_configuration import ForecastConfiguration
from posture_forecasting.domain.aggregates.posture_forecast import PostureForecast
from posture_forecasting.domain.value_objects.identifiers import TenantId


class IPostureForecastRepository(ABC):
    @abstractmethod
    async def save(self, forecast: PostureForecast, tenant_id: TenantId) -> None: ...

    @abstractmethod
    async def find_latest(self, tenant_id: TenantId) -> PostureForecast | None: ...

    @abstractmethod
    async def find_pending_accuracy_check(
        self, horizon_days: int, cutoff: datetime
    ) -> list[PostureForecast]: ...


class IForecastConfigurationRepository(ABC):
    @abstractmethod
    async def get_or_create_default(self, tenant_id: TenantId) -> ForecastConfiguration: ...
