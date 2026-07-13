"""SQLAlchemy implementation of MembershipRepository.

This repository backs the platform's tenant-isolation boundary — every
organization-scoped API request resolves its authorization here (see
api/security.py). It implements domain.identity.repository.MembershipRepository.
"""

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from redforge.domain.identity.entities import Membership
from redforge.domain.identity.value_objects import MembershipRole, MembershipStatus
from redforge.infrastructure.database.mappings import membership_mapper
from redforge.infrastructure.database.models.membership import MembershipModel
from redforge.shared.identifiers import EntityId


class SqlAlchemyMembershipRepository:
    """Async SQLAlchemy implementation of MembershipRepository.

    Each instance is scoped to a single AsyncSession (one unit of work).
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(self, membership_id: EntityId) -> Membership | None:
        stmt = select(MembershipModel).where(MembershipModel.id == str(membership_id))
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        return membership_mapper.to_entity(model) if model is not None else None

    async def get_by_user_and_org(
        self, user_id: EntityId, organization_id: EntityId
    ) -> Membership | None:
        """The tenant-isolation lookup: does this user have (any) membership
        in this organization? Returns inactive memberships too — callers
        must check `.is_active` themselves (revoked-but-visible is a
        deliberate choice so admins can audit past membership, distinct
        from "never existed").
        """
        stmt = select(MembershipModel).where(
            MembershipModel.user_id == str(user_id),
            MembershipModel.organization_id == str(organization_id),
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        return membership_mapper.to_entity(model) if model is not None else None

    async def list_by_user(self, user_id: EntityId) -> list[Membership]:
        stmt = select(MembershipModel).where(
            MembershipModel.user_id == str(user_id),
            MembershipModel.status == str(MembershipStatus.ACTIVE),
        )
        result = await self._session.execute(stmt)
        return [membership_mapper.to_entity(m) for m in result.scalars().all()]

    async def list_by_organization(self, organization_id: EntityId) -> list[Membership]:
        stmt = select(MembershipModel).where(
            MembershipModel.organization_id == str(organization_id),
            MembershipModel.status == str(MembershipStatus.ACTIVE),
        )
        result = await self._session.execute(stmt)
        return [membership_mapper.to_entity(m) for m in result.scalars().all()]

    async def exists(self, user_id: EntityId, organization_id: EntityId) -> bool:
        stmt = select(MembershipModel.id).where(
            MembershipModel.user_id == str(user_id),
            MembershipModel.organization_id == str(organization_id),
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none() is not None

    async def count_active_owners(self, organization_id: EntityId) -> int:
        stmt = select(func.count(MembershipModel.id)).where(
            MembershipModel.organization_id == str(organization_id),
            MembershipModel.role == str(MembershipRole.OWNER),
            MembershipModel.status == str(MembershipStatus.ACTIVE),
        )
        result = await self._session.execute(stmt)
        return result.scalar_one()

    async def save(self, membership: Membership) -> None:
        """Persist a new or updated Membership (insert or update by PK)."""
        model = membership_mapper.to_model(membership)
        await self._session.merge(model)
        await self._session.flush()
