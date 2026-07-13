"""PostgreSQL Dead Letter Queue — Sprint 28/31.

Durable implementation of the RuntimeDLQ protocol backed by the
dead_letter_entries table (created by migration 0008, extended by 0009).

Sprint 31 changes:
- list_pending_replay() atomically claims entries (status → in_flight) using
  SELECT FOR UPDATE SKIP LOCKED. Concurrent workers cannot pick the same entry.
  Expired reservations (reserved_until < NOW()) are re-claimable.
- mark_exhausted() sets status → exhausted (terminal). Never re-claimable.
- release_inflight() returns status → requeued after replay failure.

Design decisions:
- store() is idempotent: INSERT ON CONFLICT (entry_id) DO NOTHING.
- requeue() uses optimistic concurrency control via the version column.
- list() / depth() exclude replayed, in_flight, and exhausted entries for
  org-scoped views — operators see only actionable pending/requeued entries.
- mark_replayed() hard-deletes rows — keeps the table lean.
- All session operations use a fresh AsyncSession per call (session_factory()).
- organization_id comes from DeadLetterEntry.organization_id which is set
  by the caller at store() time. The API layer enforces JWT-scoped access.

Multi-tenant isolation:
  list() and depth() ALWAYS filter by organization_id.
  list_pending_replay() returns entries across all orgs — the replay worker
  is an internal process; organization_id is carried on each entry and
  enforced by projection engine handlers + cross-tenant check in app.py.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError

from redforge.application.platform.dead_letter_queue import DeadLetterEntryNotFoundError
from redforge.application.platform.runtime_contracts import DeadLetterEntry
from redforge.infrastructure.platform.models import DeadLetterEntryModel

if TYPE_CHECKING:
    from collections.abc import Sequence

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

# How long a worker holds an in-flight reservation before it expires.
_INFLIGHT_TTL_SECONDS = 300  # 5 minutes


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _row_to_entry(row: DeadLetterEntryModel) -> DeadLetterEntry:
    return DeadLetterEntry(
        entry_id=row.entry_id,
        source_projection=row.source_projection,
        event_id=row.event_id,
        event_type=row.event_type,
        payload=row.payload,
        error_message=row.error_message,
        retry_count=row.retry_count,
        first_failed_at=row.first_failed_at,
        last_failed_at=row.last_failed_at,
        organization_id=row.organization_id,
    )


def _to_payload_dict(payload: Any) -> dict[str, Any]:
    """Coerce payload to a JSONB-serialisable dict."""
    if isinstance(payload, dict):
        return payload
    return {"_raw": str(payload)}


class PostgreSQLDeadLetterQueue:
    """Durable DLQ backed by the dead_letter_entries PostgreSQL table.

    Satisfies the RuntimeDLQ protocol via structural subtyping.
    """

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sf = session_factory

    # ── DeadLetterStore protocol ───────────────────────────────────────────

    async def store(self, entry: DeadLetterEntry) -> None:
        """Idempotent insert — silently ignores duplicate entry_id."""
        now = _utc_now()
        row = DeadLetterEntryModel(
            entry_id=entry.entry_id,
            source_projection=entry.source_projection,
            event_id=entry.event_id,
            event_type=entry.event_type,
            payload=_to_payload_dict(entry.payload),
            error_message=entry.error_message,
            retry_count=entry.retry_count,
            status="pending",
            first_failed_at=entry.first_failed_at,
            last_failed_at=entry.last_failed_at,
            organization_id=entry.organization_id,
            version=0,
            created_at=now,
            updated_at=now,
            reserved_until=None,
            exhausted_at=None,
        )
        async with self._sf() as session:
            session.add(row)
            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()

    async def list(
        self,
        organization_id: str,
        source_projection: str | None = None,
        max_count: int | None = None,
    ) -> Sequence[DeadLetterEntry]:
        """List pending/requeued entries for an org. Excludes in_flight and exhausted."""
        async with self._sf() as session:
            q = (
                select(DeadLetterEntryModel)
                .where(
                    DeadLetterEntryModel.organization_id == organization_id,
                    DeadLetterEntryModel.status.in_(["pending", "requeued"]),
                )
                .order_by(DeadLetterEntryModel.last_failed_at.desc())
            )
            if source_projection is not None:
                q = q.where(
                    DeadLetterEntryModel.source_projection == source_projection
                )
            if max_count is not None:
                q = q.limit(max_count)
            result = await session.execute(q)
            return [_row_to_entry(row) for row in result.scalars()]

    async def requeue(self, entry_id: str) -> DeadLetterEntry:
        """Mark entry for replay and increment retry_count.

        Raises:
            DeadLetterEntryNotFoundError: if entry_id does not exist.
        """
        async with self._sf() as session:
            row = await session.get(DeadLetterEntryModel, entry_id)
            if row is None:
                raise DeadLetterEntryNotFoundError(entry_id)
            row.status = "requeued"
            row.retry_count += 1
            row.last_failed_at = _utc_now()
            row.version += 1
            row.updated_at = _utc_now()
            row.reserved_until = None
            await session.commit()
            await session.refresh(row)
            return _row_to_entry(row)

    async def discard(self, entry_id: str) -> None:
        """Hard-delete an entry.

        Raises:
            DeadLetterEntryNotFoundError: if entry_id does not exist.
        """
        async with self._sf() as session:
            row = await session.get(DeadLetterEntryModel, entry_id)
            if row is None:
                raise DeadLetterEntryNotFoundError(entry_id)
            await session.delete(row)
            await session.commit()

    async def depth(self, organization_id: str) -> int:
        """Count pending+requeued entries for an org (excludes in_flight and exhausted)."""
        async with self._sf() as session:
            q = (
                select(func.count())
                .select_from(DeadLetterEntryModel)
                .where(
                    DeadLetterEntryModel.organization_id == organization_id,
                    DeadLetterEntryModel.status.in_(["pending", "requeued"]),
                )
            )
            result = await session.execute(q)
            return result.scalar() or 0

    # ── RuntimeDLQ extensions ──────────────────────────────────────────────

    async def total_depth(self) -> int:
        """Count all pending+requeued entries across all organisations."""
        async with self._sf() as session:
            q = (
                select(func.count())
                .select_from(DeadLetterEntryModel)
                .where(DeadLetterEntryModel.status.in_(["pending", "requeued"]))
            )
            result = await session.execute(q)
            return result.scalar() or 0

    async def list_pending_replay(self, max_count: int = 100) -> Sequence[DeadLetterEntry]:
        """Atomically claim entries for replay using SELECT FOR UPDATE SKIP LOCKED.

        Entries are moved from status=requeued to status=in_flight with a
        reserved_until timestamp. Entries whose reservation has expired
        (reserved_until < NOW()) are also eligible for re-claiming.

        This prevents two concurrent workers from replaying the same entry.
        """
        now = _utc_now()
        expires_at = now + timedelta(seconds=_INFLIGHT_TTL_SECONDS)

        async with self._sf() as session, session.begin():
            # Sub-select the claimable entry IDs using SKIP LOCKED.
            # Claimable: requeued OR (in_flight AND reservation expired).
            subq = (
                select(DeadLetterEntryModel.entry_id)
                .where(

                        (DeadLetterEntryModel.status == "requeued")
                        | (
                            (DeadLetterEntryModel.status == "in_flight")
                            & (DeadLetterEntryModel.reserved_until < now)
                        )

                )
                .order_by(DeadLetterEntryModel.last_failed_at.asc())
                .limit(max_count)
                .with_for_update(skip_locked=True)
                .subquery()
            )

            stmt = (
                update(DeadLetterEntryModel)
                .where(DeadLetterEntryModel.entry_id.in_(select(subq.c.entry_id)))
                .values(
                    status="in_flight",
                    reserved_until=expires_at,
                    updated_at=now,
                    version=DeadLetterEntryModel.version + 1,
                )
                .returning(DeadLetterEntryModel)
            )
            result = await session.execute(stmt)
            rows = result.scalars().all()
            return [_row_to_entry(row) for row in rows]

    async def mark_replayed(self, entry_id: str) -> None:
        """Hard-delete an entry after successful replay."""
        async with self._sf() as session:
            row = await session.get(DeadLetterEntryModel, entry_id)
            if row is not None:
                await session.delete(row)
                await session.commit()

    async def mark_exhausted(self, entry_id: str) -> None:
        """Transition an entry to the terminal exhausted state.

        Exhausted entries are never picked up for replay again.
        Operators must inspect and discard them manually.
        """
        now = _utc_now()
        async with self._sf() as session:
            row = await session.get(DeadLetterEntryModel, entry_id)
            if row is not None:
                row.status = "exhausted"
                row.exhausted_at = now
                row.reserved_until = None
                row.updated_at = now
                row.version += 1
                await session.commit()

    async def release_inflight(self, entry_id: str) -> None:
        """Return an in-flight entry to requeued state after replay failure.

        Clears reserved_until so the entry becomes claimable on the next poll.
        """
        now = _utc_now()
        async with self._sf() as session:
            row = await session.get(DeadLetterEntryModel, entry_id)
            if row is not None:
                row.status = "requeued"
                row.reserved_until = None
                row.updated_at = now
                row.version += 1
                await session.commit()
