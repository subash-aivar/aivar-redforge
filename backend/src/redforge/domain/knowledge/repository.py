"""Repository interface for the Knowledge Item aggregate."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from redforge.domain.knowledge.entity import KnowledgeItem
    from redforge.domain.knowledge.value_objects import KnowledgeCategory, KnowledgeStatus
    from redforge.shared.identifiers import EntityId


@runtime_checkable
class KnowledgeRepository(Protocol):
    """Port for Knowledge Item persistence operations."""

    async def get_by_id(self, item_id: EntityId) -> KnowledgeItem | None:
        """Retrieve a Knowledge Item by its unique identifier."""
        ...

    async def list_by_category(
        self,
        category: KnowledgeCategory,
        status: KnowledgeStatus | None = None,
    ) -> list[KnowledgeItem]:
        """List knowledge items by category, optionally filtered by status."""
        ...

    async def search_by_tags(self, tags: list[str]) -> list[KnowledgeItem]:
        """Find published knowledge items matching any of the given tags."""
        ...

    async def save(self, item: KnowledgeItem) -> None:
        """Persist a new or updated Knowledge Item."""
        ...
