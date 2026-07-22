from __future__ import annotations

from autonomous_intelligence.application.services.intelligence_application_service import (
    IntelligenceApplicationService,
)
from autonomous_intelligence.infrastructure.llm.in_memory_llm import InMemoryLLMInferenceAdapter
from autonomous_intelligence.infrastructure.observability.metrics_store import (
    OperationalMetricsStore,
)
from autonomous_intelligence.infrastructure.persistence.in_memory_repositories import (
    InMemoryAutonomousOperationsPolicyRepository,
    InMemoryIntelligenceSuggestionRepository,
    InMemoryOptimizationModelRepository,
    InMemorySuggestionOutcomeRepository,
)
from autonomous_intelligence.infrastructure.workers.intelligence_workers import (
    IntelligenceScheduler,
    M36AnalyticsProjector,
    M36SecurityGraphWorker,
    MetricsWorker,
    ModelRetrainingWorker,
    OutcomeMeasurementWorker,
    SuggestionApplicationWorker,
    SuggestionExpiryWorker,
    SuggestionGenerationWorker,
)


class AutonomousIntelligenceContainer:
    def __init__(self) -> None:
        self.suggestions = InMemoryIntelligenceSuggestionRepository()
        self.models = InMemoryOptimizationModelRepository()
        self.outcomes = InMemorySuggestionOutcomeRepository()
        self.policies = InMemoryAutonomousOperationsPolicyRepository()
        self.llm = InMemoryLLMInferenceAdapter()
        self.event_sink: list[object] = []
        self.audit_log: list[dict[str, object]] = []
        self.metrics = OperationalMetricsStore()
        self.app = IntelligenceApplicationService(
            self.suggestions,
            self.models,
            self.outcomes,
            self.policies,
            self.llm,
            self.event_sink,
            self.audit_log,
        )
        self.generation_worker = SuggestionGenerationWorker(self.app)
        self.expiry_worker = SuggestionExpiryWorker(self.suggestions)
        self.application_worker = SuggestionApplicationWorker(self.app)
        self.outcome_worker = OutcomeMeasurementWorker(self.outcomes, self.models)
        self.retrain_worker = ModelRetrainingWorker(self.models)
        self.graph_worker = M36SecurityGraphWorker()
        self.analytics = M36AnalyticsProjector()
        self.metrics_worker = MetricsWorker()
        self.scheduler = IntelligenceScheduler(
            self.expiry_worker,
            self.outcome_worker,
            self.retrain_worker,
            self.metrics_worker,
        )
