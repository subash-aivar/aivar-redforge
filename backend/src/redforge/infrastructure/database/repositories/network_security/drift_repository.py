"""SqlAlchemy repository for the immutable NetworkDriftEvent log (M16).

Mirrors continuous_validation/drift_repository.py's SAVEPOINT-scoped
dedup-insert discipline exactly.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from redforge.domain.continuous_validation.value_objects import SecurityDriftCategory
from redforge.domain.network_security.entity import NetworkDriftEvent
from redforge.infrastructure.database.models.network_security import NetworkDriftEventModel
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncSession


def _to_entity(model: NetworkDriftEventModel) -> NetworkDriftEvent:
    return NetworkDriftEvent(
        id=EntityId.from_string(model.id),
        organization_id=EntityId.from_string(model.organization_id),
        policy_id=EntityId.from_string(model.policy_id),
        run_id=EntityId.from_string(model.run_id),
        category=SecurityDriftCategory(model.category),
        identity_key=model.identity_key,
        summary=model.summary,
        detail=model.detail,
        detected_at=model.detected_at,
    )


def _to_model(event: NetworkDriftEvent) -> NetworkDriftEventModel:
    return NetworkDriftEventModel(
        id=str(event.id),
        organization_id=str(event.organization_id),
        policy_id=str(event.policy_id),
        run_id=str(event.run_id),
        category=str(event.category),
        identity_key=event.identity_key,
        summary=event.summary,
        detail=event.detail,
        detected_at=event.detected_at,
    )


class SqlAlchemyNetworkDriftEventRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def append(self, event: NetworkDriftEvent) -> bool:
        """Returns False (a no-op, never an error) if an identical
        (run_id, category, identity_key) row already exists."""
        try:
            async with self._session.begin_nested():
                self._session.add(_to_model(event))
                await self._session.flush()
        except IntegrityError:
            return False
        return True

    async def list_for_policy(
        self, policy_id: EntityId, organization_id: EntityId, limit: int, offset: int,
    ) -> list[NetworkDriftEvent]:
        stmt = (
            select(NetworkDriftEventModel)
            .where(
                NetworkDriftEventModel.policy_id == str(policy_id),
                NetworkDriftEventModel.organization_id == str(organization_id),
            )
            .order_by(NetworkDriftEventModel.detected_at.desc())
            .limit(limit).offset(offset)
        )
        result = await self._session.execute(stmt)
        return [_to_entity(m) for m in result.scalars().all()]

    async def list_for_organization_since(
        self, organization_id: EntityId, since: datetime, limit: int,
    ) -> list[NetworkDriftEvent]:
        stmt = (
            select(NetworkDriftEventModel)
            .where(
                NetworkDriftEventModel.organization_id == str(organization_id),
                NetworkDriftEventModel.detected_at >= since,
            )
            .order_by(NetworkDriftEventModel.detected_at)
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return [_to_entity(m) for m in result.scalars().all()]
