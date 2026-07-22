from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from uuid import UUID

from autonomous_intelligence.domain.aggregates.autonomous_operations_policy import (
    AutonomousOperationsPolicy,
)
from autonomous_intelligence.domain.aggregates.intelligence_suggestion import IntelligenceSuggestion
from autonomous_intelligence.domain.aggregates.optimization_model import OptimizationModel
from autonomous_intelligence.domain.aggregates.suggestion_outcome import SuggestionOutcome
from autonomous_intelligence.domain.value_objects.enums import SuggestionTargetType
from autonomous_intelligence.domain.value_objects.identifiers import TenantId


class IIntelligenceSuggestionRepository(ABC):
    @abstractmethod
    async def save(self, suggestion: IntelligenceSuggestion, tenant_id: TenantId) -> None: ...

    @abstractmethod
    async def find_by_id(
        self, suggestion_id: UUID, tenant_id: TenantId
    ) -> IntelligenceSuggestion | None: ...

    @abstractmethod
    async def find_pending_review(
        self, tenant_id: TenantId, target_type: SuggestionTargetType | None, limit: int
    ) -> list[IntelligenceSuggestion]: ...

    @abstractmethod
    async def find_approved_pending_application(
        self, tenant_id: TenantId
    ) -> list[IntelligenceSuggestion]: ...

    @abstractmethod
    async def find_expired_pending(self, cutoff: datetime) -> list[IntelligenceSuggestion]: ...


class IOptimizationModelRepository(ABC):
    @abstractmethod
    async def save(self, model: OptimizationModel, tenant_id: TenantId) -> None: ...

    @abstractmethod
    async def find_deployed(
        self, tenant_id: TenantId, target_type: SuggestionTargetType
    ) -> OptimizationModel | None: ...

    @abstractmethod
    async def find_by_id(self, model_id: str, tenant_id: TenantId) -> OptimizationModel | None: ...


class ISuggestionOutcomeRepository(ABC):
    @abstractmethod
    async def append(self, outcome: SuggestionOutcome) -> None: ...

    @abstractmethod
    async def update_measurement(self, outcome: SuggestionOutcome, tenant_id: TenantId) -> None:
        """Persist a measurement recorded via SuggestionOutcome.record_measurement()
        on an outcome that was already append()'d. Separate from append()
        because SuggestionOutcome is conceptually append-only (append once
        when pending, then transitions in place) rather than re-inserted —
        a real backing store needs an explicit write for that transition;
        an in-memory list holding object references doesn't, which is why
        this method was missing until OutcomeMeasurementWorker's mutation
        was found to silently no-op against Postgres.
        """
        ...

    @abstractmethod
    async def find_for_suggestion(
        self, suggestion_id: UUID, tenant_id: TenantId
    ) -> list[SuggestionOutcome]: ...

    @abstractmethod
    async def find_pending_measurement(
        self, cutoff: datetime, tenant_id: TenantId
    ) -> list[SuggestionOutcome]: ...


class IAutonomousOperationsPolicyRepository(ABC):
    @abstractmethod
    async def get_or_create_default(self, tenant_id: TenantId) -> AutonomousOperationsPolicy: ...

    @abstractmethod
    async def save(self, policy: AutonomousOperationsPolicy, tenant_id: TenantId) -> None: ...
