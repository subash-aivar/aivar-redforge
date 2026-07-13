"""Repository interface for the AI Target aggregate."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from redforge.domain.ai_targets.entity import AITarget
    from redforge.domain.ai_targets.value_objects import TargetStatus
    from redforge.shared.identifiers import EntityId


@runtime_checkable
class AITargetRepository(Protocol):
    """Port for AI Target persistence operations."""

    async def get_by_id(
        self, target_id: EntityId, organization_id: EntityId
    ) -> AITarget | None:
        """Retrieve an AI Target by ID, scoped to its owning Organization.

        Returns None both when the target does not exist AND when it
        exists but belongs to a different organization — the two cases
        are indistinguishable to the caller by design (IDOR prevention:
        a caller must not learn that a target ID is valid in someone
        else's tenant).
        """
        ...

    async def list_by_organization(
        self,
        organization_id: EntityId,
        status: TargetStatus | None = None,
    ) -> list[AITarget]:
        """List AI Targets belonging to an Organization.

        Optionally filtered by status.
        """
        ...

    async def save(self, target: AITarget) -> None:
        """Persist a new or updated AI Target."""
        ...
