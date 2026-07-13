"""Read-only platform governance queries: users and organizations.

Deliberately thin — direct SQLAlchemy Core queries against the existing
UserModel/OrganizationModel tables, not a new inventory/query engine.
Returns governance metadata only (never password hashes, tokens, or any
tenant-scoped security data — findings/evidence/credentials are never
reachable from here), consistent with the "platform visibility is
governance/health data, not tenant security data" boundary established in
docs/MASTER_PLATFORM_EVOLUTION_ARCHITECTURE.md Section 5.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from sqlalchemy import func, select

from redforge.infrastructure.database.models.organization import OrganizationModel
from redforge.infrastructure.database.models.user import UserModel
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


@dataclass(frozen=True, slots=True)
class PlatformUserDTO:
    id: str
    email: str
    display_name: str
    status: str
    created_at: str


@dataclass(frozen=True, slots=True)
class PlatformOrganizationDTO:
    id: str
    name: str
    slug: str
    status: str
    plan: str
    created_at: str


class PlatformQueryService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def list_users(self, limit: int, offset: int) -> list[PlatformUserDTO]:
        async with SessionUnitOfWork(self._session_factory) as uow:
            stmt = (
                select(UserModel)
                .order_by(UserModel.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
            result = await uow.session.execute(stmt)
            models = result.scalars().all()
        return [
            PlatformUserDTO(
                id=m.id,
                email=m.email,
                display_name=m.display_name,
                status=m.status,
                created_at=m.created_at.isoformat(),
            )
            for m in models
        ]

    async def count_users(self) -> int:
        async with SessionUnitOfWork(self._session_factory) as uow:
            result = await uow.session.execute(select(func.count(UserModel.id)))
            return int(result.scalar_one())

    async def list_organizations(
        self, limit: int, offset: int
    ) -> list[PlatformOrganizationDTO]:
        async with SessionUnitOfWork(self._session_factory) as uow:
            stmt = (
                select(OrganizationModel)
                .order_by(OrganizationModel.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
            result = await uow.session.execute(stmt)
            models = result.scalars().all()
        return [
            PlatformOrganizationDTO(
                id=m.id,
                name=m.name,
                slug=m.slug,
                status=m.status,
                plan=m.plan,
                created_at=m.created_at.isoformat(),
            )
            for m in models
        ]

    async def count_organizations(self) -> int:
        async with SessionUnitOfWork(self._session_factory) as uow:
            result = await uow.session.execute(select(func.count(OrganizationModel.id)))
            return int(result.scalar_one())
