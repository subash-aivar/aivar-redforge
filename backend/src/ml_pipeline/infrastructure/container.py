"""DI container for ml_pipeline Phase 3."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ml_pipeline.application.services.ml_application_service import MLApplicationService
from ml_pipeline.infrastructure.acl.security_graph_write_adapter import (
    InMemorySecurityGraphWriteAdapter,
)
from ml_pipeline.infrastructure.events.structlog_event_publisher import (
    StructlogEventPublisher,
)
from ml_pipeline.infrastructure.persistence.in_memory_repositories import (
    InMemoryMLModelArtifactStore,
    InMemoryMLModelRepository,
    InMemoryPredictiveRiskSignalRepository,
)
from ml_pipeline.infrastructure.workers.ml_workers import (
    DriftCheckWorker,
    MLInferenceWorker,
    MLTrainingWorker,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from ml_pipeline.domain.repositories.i_ml_repositories import (
        IMLModelArtifactStore,
        IMLModelRepository,
        IPredictiveRiskSignalRepository,
    )


class MLPipelineContainer:
    models: IMLModelRepository
    signals: IPredictiveRiskSignalRepository
    artifacts: IMLModelArtifactStore

    def __init__(
        self, session_factory: async_sessionmaker[AsyncSession] | None = None
    ) -> None:
        if session_factory is not None:
            from ml_pipeline.infrastructure.persistence.postgres_repositories import (
                PgMLModelArtifactStore,
                PgMLModelRepository,
                PgPredictiveRiskSignalRepository,
            )

            self.models = PgMLModelRepository(session_factory)
            self.signals = PgPredictiveRiskSignalRepository(session_factory)
            self.artifacts = PgMLModelArtifactStore(session_factory)
        else:
            self.models = InMemoryMLModelRepository()
            self.signals = InMemoryPredictiveRiskSignalRepository()
            self.artifacts = InMemoryMLModelArtifactStore()
        self.graph = InMemorySecurityGraphWriteAdapter()
        self.events = StructlogEventPublisher()
        self.app = MLApplicationService(
            self.models, self.signals, self.artifacts, self.graph, self.events
        )
        self.training_worker = MLTrainingWorker(self.app)
        self.inference_worker = MLInferenceWorker(self.app)
        self.drift_worker = DriftCheckWorker(self.app)
