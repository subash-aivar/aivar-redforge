from __future__ import annotations

from datetime import datetime
from uuid import UUID

from autonomous_intelligence.domain.aggregates.autonomous_operations_policy import (
    AutonomousOperationsPolicy,
)
from autonomous_intelligence.domain.aggregates.intelligence_suggestion import IntelligenceSuggestion
from autonomous_intelligence.domain.aggregates.optimization_model import OptimizationModel
from autonomous_intelligence.domain.aggregates.suggestion_outcome import SuggestionOutcome
from autonomous_intelligence.domain.repositories.i_repositories import (
    IAutonomousOperationsPolicyRepository,
    IIntelligenceSuggestionRepository,
    IOptimizationModelRepository,
    ISuggestionOutcomeRepository,
)
from autonomous_intelligence.domain.value_objects.enums import (
    ModelStatus,
    SuggestionStatus,
    SuggestionTargetType,
)
from autonomous_intelligence.domain.value_objects.identifiers import TenantId


class InMemoryIntelligenceSuggestionRepository(IIntelligenceSuggestionRepository):
    def __init__(self) -> None:
        self._items: dict[str, dict[str, IntelligenceSuggestion]] = {}

    async def save(self, suggestion: IntelligenceSuggestion, tenant_id: TenantId) -> None:
        self._items.setdefault(str(tenant_id), {})[str(suggestion.suggestion_id)] = suggestion

    async def find_by_id(
        self, suggestion_id: UUID, tenant_id: TenantId
    ) -> IntelligenceSuggestion | None:
        return self._items.get(str(tenant_id), {}).get(str(suggestion_id))

    async def find_pending_review(
        self, tenant_id: TenantId, target_type: SuggestionTargetType | None, limit: int
    ) -> list[IntelligenceSuggestion]:
        rows = [
            s
            for s in self._items.get(str(tenant_id), {}).values()
            if s.status == SuggestionStatus.PENDING_REVIEW
        ]
        if target_type:
            rows = [s for s in rows if s.target_type == target_type]
        return rows[:limit]

    async def find_approved_pending_application(
        self, tenant_id: TenantId
    ) -> list[IntelligenceSuggestion]:
        return [
            s
            for s in self._items.get(str(tenant_id), {}).values()
            if s.status == SuggestionStatus.APPROVED
        ]

    async def find_expired_pending(self, cutoff: datetime) -> list[IntelligenceSuggestion]:
        out: list[IntelligenceSuggestion] = []
        for rows in self._items.values():
            for s in rows.values():
                if s.status == SuggestionStatus.PENDING_REVIEW and s.review_deadline_at < cutoff:
                    out.append(s)
        return out


class InMemoryOptimizationModelRepository(IOptimizationModelRepository):
    def __init__(self) -> None:
        self._items: dict[str, dict[str, OptimizationModel]] = {}

    async def save(self, model: OptimizationModel, tenant_id: TenantId) -> None:
        self._items.setdefault(str(tenant_id), {})[str(model.model_id)] = model

    async def find_deployed(
        self, tenant_id: TenantId, target_type: SuggestionTargetType
    ) -> OptimizationModel | None:
        for m in self._items.get(str(tenant_id), {}).values():
            if m.target_type == target_type and m.status == ModelStatus.DEPLOYED:
                return m
        return None

    async def find_by_id(self, model_id: str, tenant_id: TenantId) -> OptimizationModel | None:
        return self._items.get(str(tenant_id), {}).get(model_id)


class InMemorySuggestionOutcomeRepository(ISuggestionOutcomeRepository):
    def __init__(self) -> None:
        self._items: list[SuggestionOutcome] = []

    async def append(self, outcome: SuggestionOutcome) -> None:
        self._items.append(outcome)

    async def update_measurement(self, outcome: SuggestionOutcome, tenant_id: TenantId) -> None:
        # No-op: this store holds the same object reference append() added,
        # so record_measurement()'s in-place mutation is already visible.
        del outcome, tenant_id

    async def find_for_suggestion(
        self, suggestion_id: UUID, tenant_id: TenantId
    ) -> list[SuggestionOutcome]:
        return [
            o
            for o in self._items
            if o.suggestion_id == suggestion_id and o.tenant_id.value == tenant_id.value
        ]

    async def find_pending_measurement(
        self, cutoff: datetime, tenant_id: TenantId
    ) -> list[SuggestionOutcome]:
        del cutoff
        from autonomous_intelligence.domain.value_objects.enums import OutcomeType

        return [
            o
            for o in self._items
            if o.tenant_id.value == tenant_id.value and o.outcome_type == OutcomeType.PENDING
        ]


class InMemoryAutonomousOperationsPolicyRepository(IAutonomousOperationsPolicyRepository):
    def __init__(self) -> None:
        self._items: dict[str, AutonomousOperationsPolicy] = {}

    async def get_or_create_default(self, tenant_id: TenantId) -> AutonomousOperationsPolicy:
        key = str(tenant_id)
        if key not in self._items:
            self._items[key] = AutonomousOperationsPolicy.default(tenant_id)
        return self._items[key]

    async def save(self, policy: AutonomousOperationsPolicy, tenant_id: TenantId) -> None:
        self._items[str(tenant_id)] = policy
