"""Repository interface for the AttackPlan aggregate."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from redforge.domain.planning.entity import AttackPlan
    from redforge.shared.identifiers import EntityId


@runtime_checkable
class AttackPlanRepository(Protocol):
    """Port for AttackPlan persistence operations."""

    async def get_by_id(self, plan_id: EntityId) -> AttackPlan | None:
        """Retrieve a plan by its unique identifier."""
        ...

    async def get_active_for_target(self, target_id: EntityId) -> AttackPlan | None:
        """Retrieve the currently active (non-superseded) plan for a
        target, if one exists."""
        ...

    async def list_for_target(self, target_id: EntityId) -> list[AttackPlan]:
        """List every plan (active and superseded) ever created for a
        target, for audit/history purposes."""
        ...

    async def save(self, plan: AttackPlan) -> None:
        """Persist a new or updated (e.g. just-superseded) plan."""
        ...
