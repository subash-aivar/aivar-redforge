"""SqlAlchemy repository for runtime component health state/transitions
(M15).

`record_transition_if_changed()` is the one safety-critical method
here: it must detect a genuine HEALTHY<->UNHEALTHY flip and emit
exactly one durable transition row for it, even when multiple API
process instances poll concurrently. It does this with a row-level
lock (`SELECT ... FOR UPDATE`) on the single current-status row —
whichever instance's transaction gets there first performs the
transition and durably records it; every other concurrently-blocked
instance, once unblocked, sees the row already updated to the new
status and correctly does nothing (no duplicate transition row).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from redforge.infrastructure.database.models.security_operations import (
    RuntimeComponentHealthStateModel,
    RuntimeComponentHealthTransitionModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(frozen=True, slots=True)
class RuntimeHealthTransitionRow:
    id: str
    component_id: str
    old_status: str
    new_status: str
    occurred_at: datetime


def _to_row(model: RuntimeComponentHealthTransitionModel) -> RuntimeHealthTransitionRow:
    return RuntimeHealthTransitionRow(
        id=model.id, component_id=model.component_id, old_status=model.old_status,
        new_status=model.new_status, occurred_at=model.occurred_at,
    )


class SqlAlchemyRuntimeHealthRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def record_transition_if_changed(
        self, *, transition_id: str, component_id: str, new_status: str, now: datetime,
    ) -> str | None:
        """Returns the OLD status string if a genuine transition was
        recorded (and durably logs it), or None if this is either the
        first-ever observation of this component (baseline, not a
        transition) or the status is unchanged from last time (no
        duplicate emitted)."""
        stmt = (
            select(RuntimeComponentHealthStateModel)
            .where(RuntimeComponentHealthStateModel.component_id == component_id)
            .with_for_update()
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()

        if row is None:
            # Two instances observing this component for the very first
            # time concurrently would otherwise both see row is None and
            # both attempt the same-primary-key INSERT, raising
            # IntegrityError for the loser. ON CONFLICT DO NOTHING makes
            # the race a genuine no-op for whichever instance loses it —
            # correct either way, since this is a baseline observation,
            # not a transition to report.
            insert_stmt = (
                pg_insert(RuntimeComponentHealthStateModel)
                .values(component_id=component_id, status=new_status, updated_at=now)
                .on_conflict_do_nothing(index_elements=["component_id"])
            )
            await self._session.execute(insert_stmt)
            await self._session.flush()
            return None

        if row.status == new_status:
            return None

        old_status = row.status
        row.status = new_status
        row.updated_at = now
        self._session.add(
            RuntimeComponentHealthTransitionModel(
                id=transition_id, component_id=component_id,
                old_status=old_status, new_status=new_status, occurred_at=now,
            )
        )
        await self._session.flush()
        return old_status

    async def list_transitions_since(
        self, since: datetime, limit: int,
    ) -> list[RuntimeHealthTransitionRow]:
        stmt = (
            select(RuntimeComponentHealthTransitionModel)
            .where(RuntimeComponentHealthTransitionModel.occurred_at >= since)
            .order_by(RuntimeComponentHealthTransitionModel.occurred_at)
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return [_to_row(m) for m in result.scalars().all()]
