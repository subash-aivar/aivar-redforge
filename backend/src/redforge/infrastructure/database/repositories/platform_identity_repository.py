"""SqlAlchemy repository for the Platform Identity bounded context.

Receives an active AsyncSession. NEVER commits or rolls back — the
caller's UnitOfWork owns the transaction boundary, which is exactly what
makes the bootstrap atomic-claim pattern (see PlatformAccessService)
transactionally correct: the UPDATE claim and the follow-up INSERT run
in the same UoW-managed transaction.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import select, text

from redforge.domain.platform_identity.entity import PlatformAssignment
from redforge.domain.platform_identity.value_objects import (
    PlatformAssignmentStatus,
    PlatformRole,
)
from redforge.infrastructure.database.models.platform_identity import (
    PlatformAssignmentModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def _to_entity(model: PlatformAssignmentModel) -> PlatformAssignment:
    return PlatformAssignment(
        id=model.id,
        user_id=model.user_id,
        role=PlatformRole(model.role),
        status=PlatformAssignmentStatus(model.status),
        granted_by=model.granted_by,
        granted_at=_ensure_utc(model.granted_at),
        revoked_by=model.revoked_by,
        revoked_at=_ensure_utc(model.revoked_at) if model.revoked_at else None,
        version=model.version,
    )


class SqlAlchemyPlatformAssignmentRepository:
    """Async repository for PlatformAssignment persistence."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(self, assignment_id: str) -> PlatformAssignment | None:
        stmt = select(PlatformAssignmentModel).where(
            PlatformAssignmentModel.id == assignment_id
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        return _to_entity(model) if model else None

    async def list_active_by_user(self, user_id: str) -> list[PlatformAssignment]:
        stmt = select(PlatformAssignmentModel).where(
            PlatformAssignmentModel.user_id == user_id,
            PlatformAssignmentModel.status == PlatformAssignmentStatus.ACTIVE.value,
        )
        result = await self._session.execute(stmt)
        return [_to_entity(m) for m in result.scalars().all()]

    async def list_all(self, limit: int, offset: int) -> list[PlatformAssignment]:
        stmt = (
            select(PlatformAssignmentModel)
            .order_by(PlatformAssignmentModel.granted_at.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await self._session.execute(stmt)
        return [_to_entity(m) for m in result.scalars().all()]

    async def lock_active_by_role(self, role: PlatformRole) -> list[PlatformAssignment]:
        """SELECT ... FOR UPDATE the currently-active assignments of one
        role. Used to make last-Super-Admin-protection race-safe: two
        concurrent revokes of two different "last" active assignments
        will serialize on these row locks under READ COMMITTED, so the
        second transaction re-evaluates the count after the first commits.
        """
        stmt = (
            select(PlatformAssignmentModel)
            .where(
                PlatformAssignmentModel.role == role.value,
                PlatformAssignmentModel.status == PlatformAssignmentStatus.ACTIVE.value,
            )
            .with_for_update()
        )
        result = await self._session.execute(stmt)
        return [_to_entity(m) for m in result.scalars().all()]

    async def save(self, assignment: PlatformAssignment) -> None:
        model = PlatformAssignmentModel(
            id=assignment.id,
            user_id=assignment.user_id,
            role=assignment.role.value,
            status=assignment.status.value,
            granted_by=assignment.granted_by,
            granted_at=assignment.granted_at,
            revoked_by=assignment.revoked_by,
            revoked_at=assignment.revoked_at,
            version=assignment.version,
        )
        await self._session.merge(model)
        await self._session.flush()

    async def claim_bootstrap(self, user_id: str) -> bool:
        """Atomically claim the one-time bootstrap slot.

        Returns True iff this call won the race (the UPDATE matched the
        singleton row because consumed_at was still NULL). Returns False
        if bootstrap was already consumed — by this call or a concurrent
        one. Race-safe under Postgres row locking: a concurrent second
        UPDATE blocks on the row lock until the first transaction
        commits, then finds consumed_at already set and matches zero
        rows — not a check-then-insert race.
        """
        result = await self._session.execute(
            text(
                "UPDATE platform_bootstrap_state "
                "SET consumed_at = CURRENT_TIMESTAMP, consumed_by = :user_id "
                "WHERE id = 'singleton' AND consumed_at IS NULL "
                "RETURNING id"
            ),
            # CURRENT_TIMESTAMP is computed by the database, not bound as
            # a Python value — avoids both Python 3.12's deprecated
            # implicit sqlite3 datetime adapter (SQLite test engines) and
            # asyncpg's strict typing (a bound ISO string fails against a
            # timestamptz column). Standard SQL, portable across both
            # dialects used in this codebase.
            {"user_id": user_id},
        )
        return result.first() is not None

    async def bootstrap_is_consumed(self) -> bool:
        result = await self._session.execute(
            text("SELECT consumed_at FROM platform_bootstrap_state WHERE id = 'singleton'")
        )
        row = result.first()
        return row is not None and row[0] is not None
