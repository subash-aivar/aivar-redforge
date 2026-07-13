"""Application services for the Organization bounded context.

Coordinates UoW, domain behavior, persistence, and event publishing.
Every REST/CLI/GraphQL/MCP endpoint calls these services.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.domain.organizations.entity import Organization
from redforge.domain.organizations.exceptions import (
    OrganizationNotFoundError,
    OrganizationSlugTakenError,
)
from redforge.domain.organizations.value_objects import (
    OrganizationName,
    OrganizationPlan,
    OrganizationSlug,
)
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from redforge.application.contracts import EventPublisherPort
    from redforge.infrastructure.audit.contracts import AuditLog


# ─── DTOs ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class OrganizationDTO:
    """Application-layer representation of an Organization."""

    id: str
    name: str
    slug: str
    status: str
    plan: str
    created_at: str
    updated_at: str

    @classmethod
    def from_entity(cls, org: Organization) -> OrganizationDTO:
        return cls(
            id=str(org.id),
            name=str(org.name),
            slug=str(org.slug),
            status=str(org.status),
            plan=str(org.plan),
            created_at=org.timestamps.created_at.isoformat(),
            updated_at=org.timestamps.updated_at.isoformat(),
        )


# ─── Application Service ──────────────────────────────────────────────────────


class OrganizationService:
    """Orchestrates Organization use cases with full lifecycle management.

    Usage from any transport adapter:
        service = OrganizationService(session_factory, event_publisher)
        dto = await service.register("Acme Corp", "acme-corp", "enterprise")

    Transaction boundaries are managed by SessionUnitOfWork.
    Repositories NEVER commit — only UoW does.
    """

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        event_publisher: EventPublisherPort,
        audit_log: AuditLog | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._event_publisher = event_publisher
        self._audit_log = audit_log

    async def _audit(
        self, *, action: str, actor_id: str, organization_id: str,
        metadata: dict[str, str] | None = None,
    ) -> None:
        if self._audit_log is None:
            return
        from redforge.infrastructure.audit.contracts import AuditAction, AuditEntry

        await self._audit_log.record(AuditEntry(
            action=AuditAction(action),
            actor_id=actor_id,
            resource_type="organization",
            resource_id=organization_id,
            metadata=metadata or {},
        ))

    async def register(
        self, name: str, slug: str, plan: str = "free",
        *, created_by_user_id: str,
    ) -> OrganizationDTO:
        """Register a new Organization.

        The creating user is atomically granted an OWNER Membership in
        the same transaction — an Organization with no Owner would be a
        tenant nobody can administer, and would fail every subsequent
        authorization check (see api/security.py).
        """
        from redforge.domain.identity.entities import Membership
        from redforge.domain.identity.value_objects import MembershipRole
        from redforge.infrastructure.database.repositories.membership_repository import (
            SqlAlchemyMembershipRepository,
        )
        from redforge.infrastructure.database.repositories.organization_repository import (
            SqlAlchemyOrganizationRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyOrganizationRepository(uow.session)
            slug_vo = OrganizationSlug(slug)

            if await repo.slug_exists(slug_vo):
                raise OrganizationSlugTakenError(slug)

            org = Organization.create(
                name=OrganizationName(name),
                slug=slug_vo,
                plan=OrganizationPlan(plan),
            )
            await repo.save(org)

            membership = Membership.create(
                user_id=EntityId.from_string(created_by_user_id),
                organization_id=org.id,
                role=MembershipRole.OWNER,
            )
            membership_repo = SqlAlchemyMembershipRepository(uow.session)
            await membership_repo.save(membership)

            await uow.commit()

        events = org.collect_events() + membership.collect_events()
        await self._event_publisher.publish(events)
        await self._audit(
            action="org.created", actor_id=created_by_user_id,
            organization_id=str(org.id), metadata={"name": name, "slug": slug},
        )
        return OrganizationDTO.from_entity(org)

    async def get_by_id(self, organization_id: str) -> OrganizationDTO:
        """Retrieve an Organization by ID."""
        from redforge.infrastructure.database.repositories.organization_repository import (
            SqlAlchemyOrganizationRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyOrganizationRepository(uow.session)
            entity_id = EntityId.from_string(organization_id)
            org = await repo.get_by_id(entity_id)
            if org is None:
                raise OrganizationNotFoundError(organization_id)
            return OrganizationDTO.from_entity(org)

    async def rename(
        self, organization_id: str, new_name: str, *, actor_user_id: str = "system",
    ) -> OrganizationDTO:
        """Rename an Organization."""
        from redforge.infrastructure.database.repositories.organization_repository import (
            SqlAlchemyOrganizationRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyOrganizationRepository(uow.session)
            entity_id = EntityId.from_string(organization_id)
            org = await repo.get_by_id(entity_id)
            if org is None:
                raise OrganizationNotFoundError(organization_id)

            org.rename(OrganizationName(new_name))
            await repo.save(org)
            await uow.commit()

        events = org.collect_events()
        await self._event_publisher.publish(events)
        await self._audit(
            action="org.renamed", actor_id=actor_user_id, organization_id=organization_id,
            metadata={"new_name": new_name},
        )
        return OrganizationDTO.from_entity(org)

    async def deactivate(
        self, organization_id: str, *, actor_user_id: str = "system",
    ) -> OrganizationDTO:
        """Deactivate an Organization."""
        from redforge.infrastructure.database.repositories.organization_repository import (
            SqlAlchemyOrganizationRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyOrganizationRepository(uow.session)
            entity_id = EntityId.from_string(organization_id)
            org = await repo.get_by_id(entity_id)
            if org is None:
                raise OrganizationNotFoundError(organization_id)

            org.deactivate()
            await repo.save(org)
            await uow.commit()

        events = org.collect_events()
        await self._event_publisher.publish(events)
        await self._audit(
            action="org.deactivated", actor_id=actor_user_id, organization_id=organization_id,
        )
        return OrganizationDTO.from_entity(org)

    async def activate(
        self, organization_id: str, *, actor_user_id: str = "system",
    ) -> OrganizationDTO:
        """Activate an Organization."""
        from redforge.infrastructure.database.repositories.organization_repository import (
            SqlAlchemyOrganizationRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyOrganizationRepository(uow.session)
            entity_id = EntityId.from_string(organization_id)
            org = await repo.get_by_id(entity_id)
            if org is None:
                raise OrganizationNotFoundError(organization_id)

            org.activate()
            await repo.save(org)
            await uow.commit()

        events = org.collect_events()
        await self._event_publisher.publish(events)
        await self._audit(
            action="org.activated", actor_id=actor_user_id, organization_id=organization_id,
        )
        return OrganizationDTO.from_entity(org)

    async def suspend(
        self, organization_id: str, reason: str = "", *, actor_user_id: str = "system",
    ) -> OrganizationDTO:
        """Suspend an Organization (policy violation, billing)."""
        from redforge.infrastructure.database.repositories.organization_repository import (
            SqlAlchemyOrganizationRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyOrganizationRepository(uow.session)
            entity_id = EntityId.from_string(organization_id)
            org = await repo.get_by_id(entity_id)
            if org is None:
                raise OrganizationNotFoundError(organization_id)

            org.suspend(reason)
            await repo.save(org)
            await uow.commit()

        events = org.collect_events()
        await self._event_publisher.publish(events)
        await self._audit(
            action="org.suspended", actor_id=actor_user_id, organization_id=organization_id,
            metadata={"reason": reason},
        )
        return OrganizationDTO.from_entity(org)
