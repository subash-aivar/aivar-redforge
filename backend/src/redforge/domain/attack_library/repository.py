"""Repository interface for the Attack Definition aggregate."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from redforge.domain.attack_library.entity import AttackDefinition
    from redforge.domain.attack_library.value_objects import AttackCategory, AttackStatus
    from redforge.shared.identifiers import EntityId


@runtime_checkable
class AttackLibraryRepository(Protocol):
    """Port for Attack Definition persistence operations."""

    async def get_by_id(self, attack_id: EntityId) -> AttackDefinition | None:
        """Retrieve an attack definition by its unique identifier."""
        ...

    async def list_by_category(
        self,
        category: AttackCategory,
        status: AttackStatus | None = None,
    ) -> list[AttackDefinition]:
        """List attacks by category, optionally filtered by status."""
        ...

    async def search_by_tags(self, tags: list[str]) -> list[AttackDefinition]:
        """Find published attacks matching any of the given tags."""
        ...

    async def list_executable(self) -> list[AttackDefinition]:
        """List all attacks available for execution (published + deprecated)."""
        ...

    async def save(self, attack: AttackDefinition) -> None:
        """Persist a new or updated attack definition."""
        ...
