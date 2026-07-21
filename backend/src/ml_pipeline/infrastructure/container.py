"""DI container for ml_pipeline Phase 3."""

from __future__ import annotations

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


class MLPipelineContainer:
    def __init__(self) -> None:
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
