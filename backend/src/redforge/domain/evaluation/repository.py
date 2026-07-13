"""Repository interface for the EvaluationResult aggregate."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from redforge.domain.evaluation.entity import EvaluationResult
    from redforge.shared.identifiers import EntityId


@runtime_checkable
class EvaluationResultRepository(Protocol):
    """Port for EvaluationResult persistence operations."""

    async def get_by_id(self, evaluation_id: EntityId) -> EvaluationResult | None:
        """Retrieve an evaluation result by its unique identifier."""
        ...

    async def get_active_for_attack(
        self, target_id: EntityId, attack_id: EntityId,
    ) -> EvaluationResult | None:
        """Retrieve the currently active (non-superseded) evaluation
        result for a (target, attack) pair, if one exists."""
        ...

    async def list_for_plan(self, attack_plan_id: EntityId) -> list[EvaluationResult]:
        """List every evaluation result produced for an attack plan."""
        ...

    async def save(self, result: EvaluationResult) -> None:
        """Persist a new or updated (e.g. just-superseded) result."""
        ...
