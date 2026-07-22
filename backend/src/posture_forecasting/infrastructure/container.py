from __future__ import annotations

from typing import TYPE_CHECKING

from posture_forecasting.application.services.forecast_application_service import (
    ForecastApplicationService,
)
from posture_forecasting.domain.services.forecast_accuracy_service import ForecastAccuracyService
from posture_forecasting.infrastructure.persistence.in_memory_repositories import (
    InMemoryForecastConfigurationRepository,
    InMemoryPostureForecastRepository,
)
from posture_forecasting.infrastructure.workers.forecast_workers import (
    ForecastAccuracyWorker,
    ForecastScheduler,
    PostureForecastWorker,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from posture_forecasting.domain.repositories.i_repositories import (
        IForecastConfigurationRepository,
        IPostureForecastRepository,
    )


class PostureForecastingContainer:
    forecasts: IPostureForecastRepository
    configs: IForecastConfigurationRepository

    def __init__(
        self, session_factory: async_sessionmaker[AsyncSession] | None = None
    ) -> None:
        if session_factory is not None:
            from posture_forecasting.infrastructure.persistence.postgres_repositories import (
                PgForecastConfigurationRepository,
                PgPostureForecastRepository,
            )

            self.forecasts = PgPostureForecastRepository(session_factory)
            self.configs = PgForecastConfigurationRepository(session_factory)
        else:
            self.forecasts = InMemoryPostureForecastRepository()
            self.configs = InMemoryForecastConfigurationRepository()
        self.event_sink: list[object] = []
        self.app = ForecastApplicationService(self.forecasts, self.configs, self.event_sink)
        self.forecast_worker = PostureForecastWorker(self.app)
        self.accuracy_worker = ForecastAccuracyWorker(self.forecasts, ForecastAccuracyService())
        self.scheduler = ForecastScheduler(self.forecast_worker, self.accuracy_worker)
