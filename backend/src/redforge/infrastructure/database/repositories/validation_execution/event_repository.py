"""SqlAlchemy repository for the immutable ExecutionEvent log.

Receives an active AsyncSession. NEVER commits or rolls back. There is
no update()/delete() method anywhere in this repository by design —
events are append-only.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import func, select

from redforge.infrastructure.database.mappings.validation_execution_mapper import (
    event_to_entity,
    event_to_model,
)
from redforge.infrastructure.database.models.validation_execution import (
    ValidationExecutionEventModel,
)

if TYPE_CHECKING:
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncSession

    from redforge.domain.validation_execution.execution_event import ExecutionEvent
    from redforge.shared.identifiers import EntityId


class SqlAlchemyExecutionEventRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def append(self, event: ExecutionEvent) -> None:
        self._session.add(event_to_model(event))
        await self._session.flush()

    async def next_sequence(self, execution_id: EntityId) -> int:
        stmt = select(func.count()).where(
            ValidationExecutionEventModel.execution_id == str(execution_id)
        )
        result = await self._session.execute(stmt)
        return (result.scalar_one() or 0) + 1

    async def list_for_execution(
        self, execution_id: EntityId, organization_id: EntityId, after_sequence: int, limit: int,
    ) -> list[ExecutionEvent]:
        stmt = (
            select(ValidationExecutionEventModel)
            .where(
                ValidationExecutionEventModel.execution_id == str(execution_id),
                ValidationExecutionEventModel.organization_id == str(organization_id),
                ValidationExecutionEventModel.sequence > after_sequence,
            )
            .order_by(ValidationExecutionEventModel.sequence.asc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return [event_to_entity(m) for m in result.scalars().all()]

    async def list_for_organization_since(
        self, organization_id: EntityId, since: datetime, limit: int,
    ) -> list[ExecutionEvent]:
        """Org-wide, cross-execution query ordered by occurred_at — used
        only by the M15 Security Operations cross-domain feed merge
        (application/security_operations/stream_service.py). Per-
        execution reads should prefer list_for_execution()'s more
        selective (execution_id, sequence) index."""
        stmt = (
            select(ValidationExecutionEventModel)
            .where(
                ValidationExecutionEventModel.organization_id == str(organization_id),
                ValidationExecutionEventModel.occurred_at >= since,
            )
            .order_by(ValidationExecutionEventModel.occurred_at.asc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return [event_to_entity(m) for m in result.scalars().all()]
