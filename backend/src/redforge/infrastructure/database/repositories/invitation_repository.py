"""SQLAlchemy implementation of InvitationRepository."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from redforge.domain.identity.entities import Invitation
from redforge.domain.identity.value_objects import Email, InvitationStatus
from redforge.infrastructure.database.mappings import invitation_mapper
from redforge.infrastructure.database.models.invitation import InvitationModel
from redforge.shared.identifiers import EntityId


class SqlAlchemyInvitationRepository:
    """Async SQLAlchemy implementation of InvitationRepository.

    Each instance is scoped to a single AsyncSession (one unit of work).
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(self, invitation_id: EntityId) -> Invitation | None:
        stmt = select(InvitationModel).where(InvitationModel.id == str(invitation_id))
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        return invitation_mapper.to_entity(model) if model is not None else None

    async def get_by_token_hash(self, token_hash: str) -> Invitation | None:
        stmt = select(InvitationModel).where(InvitationModel.token_hash == token_hash)
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        return invitation_mapper.to_entity(model) if model is not None else None

    async def get_pending_by_org_and_email(
        self, organization_id: EntityId, email: Email
    ) -> Invitation | None:
        stmt = select(InvitationModel).where(
            InvitationModel.organization_id == str(organization_id),
            InvitationModel.email == str(email),
            InvitationModel.status == str(InvitationStatus.PENDING),
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        return invitation_mapper.to_entity(model) if model is not None else None

    async def list_by_organization(
        self, organization_id: EntityId, status: str | None = None
    ) -> list[Invitation]:
        stmt = select(InvitationModel).where(
            InvitationModel.organization_id == str(organization_id),
        )
        if status is not None:
            stmt = stmt.where(InvitationModel.status == status)
        stmt = stmt.order_by(InvitationModel.created_at.desc())
        result = await self._session.execute(stmt)
        return [invitation_mapper.to_entity(m) for m in result.scalars().all()]

    async def save(self, invitation: Invitation) -> None:
        model = invitation_mapper.to_model(invitation)
        await self._session.merge(model)
        await self._session.flush()
