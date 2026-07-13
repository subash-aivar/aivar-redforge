"""SqlAlchemy repository for the immutable SecurityDriftEvent log (M14).

Receives an active AsyncSession. NEVER commits, and never rolls back
the session's own outer transaction — a duplicate `append()` inside a
multi-event batch (see SecurityDriftService.persist()) uses its own
SAVEPOINT so recovering from ONE duplicate never discards any other
event already flushed earlier in the same batch/session. No
update()/delete() anywhere — the change feed is append-only, matching
ExecutionEvent's own convention.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from redforge.infrastructure.database.mappings.continuous_validation_mapper import (
    drift_event_to_entity,
    drift_event_to_model,
)
from redforge.infrastructure.database.models.continuous_validation import SecurityDriftEventModel

if TYPE_CHECKING:
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncSession

    from redforge.domain.continuous_validation.entity import SecurityDriftEvent
    from redforge.shared.identifiers import EntityId


class SqlAlchemySecurityDriftEventRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def append(self, event: SecurityDriftEvent) -> bool:
        """Insert one drift event. Returns False (a documented no-op,
        never an error) if an identical (execution_id, category,
        identity_key) row already exists — the database-enforced dedup
        identity, never re-derived in application code. The insert and
        flush happen inside their own SAVEPOINT (`begin_nested()`) so
        that if it raises, only this one insert is undone — any other
        event already flushed earlier in the same session/batch is
        untouched. The IntegrityError must be caught OUTSIDE the
        `async with` block: only letting it propagate through
        `begin_nested()`'s own `__aexit__` triggers the SAVEPOINT
        rollback; catching it inside would make the block exit
        normally and try to RELEASE (commit) the SAVEPOINT instead."""
        try:
            async with self._session.begin_nested():
                self._session.add(drift_event_to_model(event))
                await self._session.flush()
        except IntegrityError:
            return False
        return True

    async def list_for_policy(
        self,
        continuous_policy_id: EntityId,
        organization_id: EntityId,
        limit: int,
        offset: int,
    ) -> list[SecurityDriftEvent]:
        stmt = (
            select(SecurityDriftEventModel)
            .where(
                SecurityDriftEventModel.continuous_policy_id == str(continuous_policy_id),
                SecurityDriftEventModel.organization_id == str(organization_id),
            )
            .order_by(SecurityDriftEventModel.detected_at.desc())
            .limit(limit).offset(offset)
        )
        result = await self._session.execute(stmt)
        return [drift_event_to_entity(m) for m in result.scalars().all()]

    async def list_for_organization(
        self,
        organization_id: EntityId,
        limit: int,
        offset: int,
    ) -> list[SecurityDriftEvent]:
        """Org-wide change feed — every drift event across every policy,
        newest first. Used by the change-feed endpoint; per-policy
        reads should prefer list_for_policy()'s more selective index."""
        stmt = (
            select(SecurityDriftEventModel)
            .where(SecurityDriftEventModel.organization_id == str(organization_id))
            .order_by(SecurityDriftEventModel.detected_at.desc())
            .limit(limit).offset(offset)
        )
        result = await self._session.execute(stmt)
        return [drift_event_to_entity(m) for m in result.scalars().all()]

    async def list_for_organization_since(
        self, organization_id: EntityId, since: datetime, limit: int,
    ) -> list[SecurityDriftEvent]:
        """Ascending-order, since-cursor variant used only by the M15
        Security Operations cross-domain feed merge
        (application/security_operations/stream_service.py)."""
        stmt = (
            select(SecurityDriftEventModel)
            .where(
                SecurityDriftEventModel.organization_id == str(organization_id),
                SecurityDriftEventModel.detected_at >= since,
            )
            .order_by(SecurityDriftEventModel.detected_at.asc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return [drift_event_to_entity(m) for m in result.scalars().all()]

    async def count_for_organization_since(self, organization_id: EntityId, since: datetime) -> int:
        """Real COUNT(*) for the M15 Security Operations summary's
        bounded-period drift metric — never a client-side tally over a
        paginated page."""
        stmt = select(func.count(SecurityDriftEventModel.id)).where(
            SecurityDriftEventModel.organization_id == str(organization_id),
            SecurityDriftEventModel.detected_at >= since,
        )
        result = await self._session.execute(stmt)
        return int(result.scalar_one() or 0)

    async def get_for_organization(
        self, drift_event_id: EntityId, organization_id: EntityId,
    ) -> SecurityDriftEvent | None:
        stmt = select(SecurityDriftEventModel).where(
            SecurityDriftEventModel.id == str(drift_event_id),
            SecurityDriftEventModel.organization_id == str(organization_id),
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        return drift_event_to_entity(model) if model is not None else None
