"""SQLAlchemy implementation of AITargetRepository."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from redforge.domain.ai_targets.entity import AITarget
from redforge.domain.ai_targets.value_objects import TargetStatus
from redforge.infrastructure.database.mappings import ai_target_mapper
from redforge.infrastructure.database.models.ai_target import AITargetModel
from redforge.shared.identifiers import EntityId


class SqlAlchemyAITargetRepository:
    """Async SQLAlchemy implementation of AITargetRepository."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(
        self, target_id: EntityId, organization_id: EntityId
    ) -> AITarget | None:
        stmt = select(AITargetModel).where(
            AITargetModel.id == str(target_id),
            AITargetModel.organization_id == str(organization_id),
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        if model is None:
            return None
        return ai_target_mapper.to_entity(model)

    async def list_by_organization(
        self,
        organization_id: EntityId,
        status: TargetStatus | None = None,
    ) -> list[AITarget]:
        stmt = select(AITargetModel).where(
            AITargetModel.organization_id == str(organization_id)
        )
        if status is not None:
            stmt = stmt.where(AITargetModel.status == str(status))
        result = await self._session.execute(stmt)
        models = result.scalars().all()
        return [ai_target_mapper.to_entity(m) for m in models]

    async def save(self, target: AITarget) -> None:
        model = ai_target_mapper.to_model(target)
        await self._session.merge(model)
        await self._session.flush()
