"""PlatformGovernanceService — M2 user and organization governance.

Reuses the EXISTING `User`/`Organization` domain entities and their
existing `suspend()`/`activate()` transitions (Sprint 1-era organization
lifecycle, User entity lifecycle) rather than inventing a second,
platform-specific status system. This service is the platform-governance
*entry point* to those existing transitions — it does not duplicate
their invariants.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.core.exceptions import ValidationError
from redforge.domain.identity.exceptions import UserNotFoundError
from redforge.infrastructure.audit.contracts import AuditAction, AuditEntry
from redforge.infrastructure.audit.platform_audit_log import PostgresPlatformAuditLog
from redforge.infrastructure.database.repositories.user_repository import (
    SqlAlchemyUserRepository,
)
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from redforge.application.organizations import OrganizationService


@dataclass(frozen=True, slots=True)
class PlatformUserDetailDTO:
    id: str
    email: str
    display_name: str
    status: str
    created_at: str
    updated_at: str


class PlatformGovernanceService:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        organization_service: OrganizationService,
    ) -> None:
        self._session_factory = session_factory
        self._organization_service = organization_service

    async def get_user_detail(self, user_id: str) -> PlatformUserDetailDTO:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyUserRepository(uow.session)
            user = await repo.get_by_id(EntityId.from_string(user_id))
        if user is None:
            raise UserNotFoundError(user_id)
        return PlatformUserDetailDTO(
            id=str(user.id),
            email=str(user.email),
            display_name=user.display_name,
            status=str(user.status),
            created_at=user.timestamps.created_at.isoformat(),
            updated_at=user.timestamps.updated_at.isoformat(),
        )

    async def suspend_user(
        self, target_user_id: str, actor_id: str, reason: str = "",
    ) -> PlatformUserDetailDTO:
        if target_user_id == actor_id:
            # Prevents an admin from accidentally locking themselves out
            # of the only usable platform governance path — the same
            # reasoning as M1's last-Super-Admin revoke protection,
            # applied to self-suspension specifically.
            raise ValidationError(
                "You cannot suspend your own account through platform governance."
            )
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyUserRepository(uow.session)
            user = await repo.get_by_id(EntityId.from_string(target_user_id))
            if user is None:
                raise UserNotFoundError(target_user_id)

            user.suspend()
            await repo.save(user)

            audit = PostgresPlatformAuditLog(uow.session)
            await audit.record(
                AuditEntry(
                    action=AuditAction.PLATFORM_USER_SUSPENDED,
                    actor_id=actor_id,
                    resource_type="user",
                    resource_id=target_user_id,
                    metadata={"outcome": "success", "reason": reason},
                )
            )
            await uow.commit()

        return await self.get_user_detail(target_user_id)

    async def reactivate_user(
        self, target_user_id: str, actor_id: str,
    ) -> PlatformUserDetailDTO:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyUserRepository(uow.session)
            user = await repo.get_by_id(EntityId.from_string(target_user_id))
            if user is None:
                raise UserNotFoundError(target_user_id)

            user.activate()
            await repo.save(user)

            audit = PostgresPlatformAuditLog(uow.session)
            await audit.record(
                AuditEntry(
                    action=AuditAction.PLATFORM_USER_REACTIVATED,
                    actor_id=actor_id,
                    resource_type="user",
                    resource_id=target_user_id,
                    metadata={"outcome": "success"},
                )
            )
            await uow.commit()

        return await self.get_user_detail(target_user_id)

    # ── Organization governance — thin wrapper over the existing,
    # already-battle-tested OrganizationService.suspend()/activate() ──────────

    async def suspend_organization(
        self, organization_id: str, actor_id: str, reason: str = "",
    ) -> None:
        await self._organization_service.suspend(
            organization_id, reason, actor_user_id=actor_id,
        )
        # OrganizationService.suspend() already audits via "org.suspended";
        # add the platform-governance-specific action too, so the platform
        # audit view (distinct from any future tenant-facing audit view)
        # shows this was a PLATFORM governance action, not a tenant
        # self-service one.
        async with SessionUnitOfWork(self._session_factory) as uow:
            audit = PostgresPlatformAuditLog(uow.session)
            await audit.record(
                AuditEntry(
                    action=AuditAction.PLATFORM_ORG_SUSPENDED,
                    actor_id=actor_id,
                    resource_type="organization",
                    resource_id=organization_id,
                    metadata={"outcome": "success", "reason": reason},
                )
            )
            await uow.commit()

    async def reactivate_organization(self, organization_id: str, actor_id: str) -> None:
        await self._organization_service.activate(organization_id, actor_user_id=actor_id)
        async with SessionUnitOfWork(self._session_factory) as uow:
            audit = PostgresPlatformAuditLog(uow.session)
            await audit.record(
                AuditEntry(
                    action=AuditAction.PLATFORM_ORG_REACTIVATED,
                    actor_id=actor_id,
                    resource_type="organization",
                    resource_id=organization_id,
                    metadata={"outcome": "success"},
                )
            )
            await uow.commit()
