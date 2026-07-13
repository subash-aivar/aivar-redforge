"""Application services for the AI Target bounded context."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.domain.ai_targets.entity import AITarget
from redforge.domain.ai_targets.exceptions import TargetNotFoundError
from redforge.domain.ai_targets.value_objects import (
    EndpointUrl,
    Provider,
    TargetName,
    TargetType,
)
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from redforge.application.contracts import EventPublisherPort


@dataclass(frozen=True, slots=True)
class AITargetDTO:
    """Application-layer representation of an AI Target."""

    id: str
    organization_id: str
    name: str
    description: str
    target_type: str
    provider: str
    endpoint: str
    status: str
    tags: list[str]
    created_at: str
    updated_at: str

    @classmethod
    def from_entity(cls, target: AITarget) -> AITargetDTO:
        return cls(
            id=str(target.id),
            organization_id=str(target.organization_id),
            name=str(target.name),
            description=target.description,
            target_type=str(target.target_type),
            provider=str(target.provider),
            endpoint=str(target.endpoint),
            status=str(target.status),
            tags=sorted(str(t) for t in target.tags),
            created_at=target.timestamps.created_at.isoformat(),
            updated_at=target.timestamps.updated_at.isoformat(),
        )


class AITargetService:
    """Orchestrates AI Target use cases.

    Transaction boundaries are managed by SessionUnitOfWork.
    Repositories NEVER commit — only UoW does.
    """

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        event_publisher: EventPublisherPort,
    ) -> None:
        self._session_factory = session_factory
        self._event_publisher = event_publisher

    async def register(
        self,
        organization_id: str,
        name: str,
        description: str,
        target_type: str,
        provider: str,
        endpoint: str,
        auth_reference: str | None = None,
    ) -> AITargetDTO:
        """Register a new AI Target."""
        from redforge.infrastructure.database.repositories.ai_target_repository import (
            SqlAlchemyAITargetRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyAITargetRepository(uow.session)
            target = AITarget.register(
                organization_id=EntityId.from_string(organization_id),
                name=TargetName(name),
                description=description,
                target_type=TargetType(target_type),
                provider=Provider(provider),
                endpoint=EndpointUrl(endpoint),
                auth_reference=auth_reference,
            )
            await repo.save(target)
            await uow.commit()

        events = target.collect_events()
        await self._event_publisher.publish(events)
        return AITargetDTO.from_entity(target)

    async def get_by_id(self, target_id: str, organization_id: str) -> AITargetDTO:
        """Retrieve an AI Target by ID, scoped to the caller's organization."""
        from redforge.infrastructure.database.repositories.ai_target_repository import (
            SqlAlchemyAITargetRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyAITargetRepository(uow.session)
            entity_id = EntityId.from_string(target_id)
            org_id = EntityId.from_string(organization_id)
            target = await repo.get_by_id(entity_id, org_id)
            if target is None:
                raise TargetNotFoundError(target_id)
            return AITargetDTO.from_entity(target)

    async def deactivate(self, target_id: str, organization_id: str) -> AITargetDTO:
        """Deactivate an AI Target, scoped to the caller's organization."""
        from redforge.infrastructure.database.repositories.ai_target_repository import (
            SqlAlchemyAITargetRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyAITargetRepository(uow.session)
            entity_id = EntityId.from_string(target_id)
            org_id = EntityId.from_string(organization_id)
            target = await repo.get_by_id(entity_id, org_id)
            if target is None:
                raise TargetNotFoundError(target_id)

            target.deactivate()
            await repo.save(target)
            await uow.commit()

        events = target.collect_events()
        await self._event_publisher.publish(events)
        return AITargetDTO.from_entity(target)

    async def list_by_organization(
        self, organization_id: str
    ) -> list[AITargetDTO]:
        """List all AI Targets for an Organization."""
        from redforge.infrastructure.database.repositories.ai_target_repository import (
            SqlAlchemyAITargetRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyAITargetRepository(uow.session)
            entity_id = EntityId.from_string(organization_id)
            targets = await repo.list_by_organization(entity_id)
            return [AITargetDTO.from_entity(t) for t in targets]
