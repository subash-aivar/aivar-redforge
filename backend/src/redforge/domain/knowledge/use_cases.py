"""Application use cases for the Knowledge bounded context."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.domain.knowledge.entity import KnowledgeItem
from redforge.domain.knowledge.exceptions import KnowledgeNotFoundError
from redforge.domain.knowledge.value_objects import (
    KnowledgeCategory,
    KnowledgeReference,
    KnowledgeSource,
    KnowledgeVersion,
)
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from redforge.domain.knowledge.events import KnowledgeEvent
    from redforge.domain.knowledge.repository import KnowledgeRepository


@dataclass(frozen=True, slots=True)
class CreateKnowledgeCommand:
    """Input for creating a knowledge item."""

    title: str
    description: str
    category: str
    source: str = "builtin"
    version: str = "1.0.0"


@dataclass(frozen=True, slots=True)
class KnowledgeResult:
    """Read-only representation of a Knowledge Item."""

    id: str
    title: str
    description: str
    category: str
    version: str
    source: str
    status: str
    tags: list[str]
    is_usable: bool
    created_at: str
    updated_at: str

    @classmethod
    def from_entity(cls, item: KnowledgeItem) -> KnowledgeResult:
        return cls(
            id=str(item.id),
            title=item.title,
            description=item.description,
            category=str(item.category),
            version=str(item.version),
            source=str(item.source),
            status=str(item.status),
            tags=sorted(item.tags),
            is_usable=item.is_usable,
            created_at=item.timestamps.created_at.isoformat(),
            updated_at=item.timestamps.updated_at.isoformat(),
        )


class CreateKnowledgeUseCase:
    """Create a new knowledge item in DRAFT status."""

    def __init__(self, repository: KnowledgeRepository) -> None:
        self._repository = repository

    async def execute(
        self, command: CreateKnowledgeCommand
    ) -> tuple[KnowledgeResult, list[KnowledgeEvent]]:
        item = KnowledgeItem.create(
            title=command.title,
            description=command.description,
            category=KnowledgeCategory(command.category),
            source=KnowledgeSource(command.source),
            version=KnowledgeVersion.from_string(command.version),
        )
        await self._repository.save(item)
        events = item.collect_events()
        return KnowledgeResult.from_entity(item), events


class PublishKnowledgeUseCase:
    """Publish a draft knowledge item."""

    def __init__(self, repository: KnowledgeRepository) -> None:
        self._repository = repository

    async def execute(
        self, item_id: str
    ) -> tuple[KnowledgeResult, list[KnowledgeEvent]]:
        entity_id = EntityId.from_string(item_id)
        item = await self._repository.get_by_id(entity_id)
        if item is None:
            raise KnowledgeNotFoundError(item_id)
        item.publish()
        await self._repository.save(item)
        events = item.collect_events()
        return KnowledgeResult.from_entity(item), events


class ArchiveKnowledgeUseCase:
    """Archive a published knowledge item."""

    def __init__(self, repository: KnowledgeRepository) -> None:
        self._repository = repository

    async def execute(
        self, item_id: str
    ) -> tuple[KnowledgeResult, list[KnowledgeEvent]]:
        entity_id = EntityId.from_string(item_id)
        item = await self._repository.get_by_id(entity_id)
        if item is None:
            raise KnowledgeNotFoundError(item_id)
        item.archive()
        await self._repository.save(item)
        events = item.collect_events()
        return KnowledgeResult.from_entity(item), events


class SupersedeKnowledgeUseCase:
    """Mark a knowledge item as superseded by a newer version."""

    def __init__(self, repository: KnowledgeRepository) -> None:
        self._repository = repository

    async def execute(
        self, item_id: str, new_item_id: str
    ) -> tuple[KnowledgeResult, list[KnowledgeEvent]]:
        entity_id = EntityId.from_string(item_id)
        item = await self._repository.get_by_id(entity_id)
        if item is None:
            raise KnowledgeNotFoundError(item_id)
        item.supersede(EntityId.from_string(new_item_id))
        await self._repository.save(item)
        events = item.collect_events()
        return KnowledgeResult.from_entity(item), events


class TagKnowledgeUseCase:
    """Add a tag to a knowledge item."""

    def __init__(self, repository: KnowledgeRepository) -> None:
        self._repository = repository

    async def execute(
        self, item_id: str, tag: str
    ) -> tuple[KnowledgeResult, list[KnowledgeEvent]]:
        entity_id = EntityId.from_string(item_id)
        item = await self._repository.get_by_id(entity_id)
        if item is None:
            raise KnowledgeNotFoundError(item_id)
        item.tag(tag)
        await self._repository.save(item)
        events = item.collect_events()
        return KnowledgeResult.from_entity(item), events


class LinkReferenceUseCase:
    """Attach a reference link to a knowledge item."""

    def __init__(self, repository: KnowledgeRepository) -> None:
        self._repository = repository

    async def execute(
        self, item_id: str, url: str, title: str, reference_type: str = "documentation"
    ) -> tuple[KnowledgeResult, list[KnowledgeEvent]]:
        entity_id = EntityId.from_string(item_id)
        item = await self._repository.get_by_id(entity_id)
        if item is None:
            raise KnowledgeNotFoundError(item_id)
        item.link_reference(KnowledgeReference(
            url=url, title=title, reference_type=reference_type
        ))
        await self._repository.save(item)
        events = item.collect_events()
        return KnowledgeResult.from_entity(item), events


class GetKnowledgeUseCase:
    """Retrieve a knowledge item by id."""

    def __init__(self, repository: KnowledgeRepository) -> None:
        self._repository = repository

    async def execute(self, item_id: str) -> KnowledgeResult:
        entity_id = EntityId.from_string(item_id)
        item = await self._repository.get_by_id(entity_id)
        if item is None:
            raise KnowledgeNotFoundError(item_id)
        return KnowledgeResult.from_entity(item)
