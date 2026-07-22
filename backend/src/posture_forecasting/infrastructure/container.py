from __future__ import annotations

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


class PostureForecastingContainer:
    def __init__(self) -> None:
        self.forecasts = InMemoryPostureForecastRepository()
        self.configs = InMemoryForecastConfigurationRepository()
        self.event_sink: list[object] = []
        self.app = ForecastApplicationService(self.forecasts, self.configs, self.event_sink)
        self.forecast_worker = PostureForecastWorker(self.app)
        self.accuracy_worker = ForecastAccuracyWorker(self.forecasts, ForecastAccuracyService())
        self.scheduler = ForecastScheduler(self.forecast_worker, self.accuracy_worker)
