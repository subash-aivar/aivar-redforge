"""PostgreSQL EventStore implementation — Sprint 25.

Implements the EventStore protocol from application/platform/contracts.py
using SQLAlchemy 2.x async sessions against a PostgreSQL database.

Concurrency strategy:
    Optimistic concurrency via UNIQUE(stream_id, stream_position).
    When two writers try to append at the same stream_position concurrently,
    PostgreSQL raises IntegrityError (unique_violation) which is translated
    to OptimisticConcurrencyError. No application-level locking needed.

    For expected_stream_version checks: we first SELECT MAX(stream_position)
    within the transaction, compare, then INSERT. The unique constraint
    catches any race that occurs between the SELECT and INSERT.

Global position:
    Assigned by a dedicated PostgreSQL sequence (platform_events_global_pos_seq)
    via NEXTVAL(). This guarantees uniqueness but NOT strict monotonicity
    in commit order (committed at 5 may be visible before committed at 3
    under concurrent transactions). Projections must handle small gaps.

    For projections requiring strict catch-up, use the global_position
    column with a brief re-read on gaps (handled by the ReplayEngine).

Multi-tenancy:
    Every query filters by organization_id. Reading across organizations
    raises MultiTenantViolationError on detection.

Design rules:
- No domain logic in this file.
- All async — uses asyncpg via SQLAlchemy async session.
- Session is injected (never created here).
- Serialisation: payload → JSON round-trip (dict ↔ JSONB).
- Metadata: serialised via EventMetadataSerializer.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import func, select, text, update
from sqlalchemy.exc import IntegrityError

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

from redforge.domain.platform.events import EventBatch, EventEnvelope
from redforge.domain.platform.exceptions import (
    DuplicateEventError,
    MultiTenantViolationError,
    OptimisticConcurrencyError,
    StreamNotFoundError,
)
from redforge.domain.platform.value_objects import (
    CausationId,
    CorrelationId,
    EventMetadata,
    EventVersion,
)
from redforge.infrastructure.platform.models import PlatformEventModel


def _utc_now() -> datetime:
    return datetime.now(UTC)


# ── Serialisation helpers ──────────────────────────────────────────────────


def _serialize_metadata(meta: EventMetadata) -> dict[str, Any]:
    return {
        "correlation_id": str(meta.correlation_id),
        "causation_id": str(meta.causation_id) if meta.causation_id else None,
        "schema_version": str(meta.schema_version),
        "actor_id": meta.actor_id,
        "actor_type": meta.actor_type,
        "source_service": meta.source_service,
        "custom": list(meta.custom),
    }


def _deserialize_metadata(data: dict[str, Any]) -> EventMetadata:
    corr = CorrelationId.from_string(data["correlation_id"])
    caus: CausationId | None = None
    if data.get("causation_id"):
        caus = CausationId.from_string(data["causation_id"])

    sv_raw = data.get("schema_version", "1.0")
    schema_version = EventVersion.from_string(sv_raw) if sv_raw else EventVersion.v1()

    custom_raw = data.get("custom", [])
    custom: tuple[tuple[str, str], ...] = tuple(
        (str(k), str(v)) for k, v in custom_raw
    )

    return EventMetadata(
        correlation_id=corr,
        causation_id=caus,
        schema_version=schema_version,
        actor_id=data.get("actor_id"),
        actor_type=data.get("actor_type"),
        source_service=data.get("source_service", "redforge"),
        custom=custom,
    )


def _serialize_payload(payload: object) -> dict[str, Any]:
    if isinstance(payload, dict):
        return dict(payload)
    if hasattr(payload, "__dict__"):
        return dict(payload.__dict__)
    if hasattr(payload, "_asdict"):
        return dict(payload._asdict())
    return {"__raw__": json.dumps(payload, default=str)}


def _model_to_envelope(row: PlatformEventModel) -> EventEnvelope:
    return EventEnvelope(
        event_id=row.event_id,
        stream_id=row.stream_id,
        stream_position=row.stream_position,
        global_position=row.global_position,
        event_type=row.event_type,
        aggregate_type=row.aggregate_type,
        aggregate_id=row.aggregate_id,
        organization_id=row.organization_id,
        payload=row.payload,
        metadata=_deserialize_metadata(row.metadata_),
        occurred_at=row.occurred_at.replace(tzinfo=UTC) if row.occurred_at.tzinfo is None
        else row.occurred_at,
        recorded_at=row.recorded_at.replace(tzinfo=UTC) if row.recorded_at.tzinfo is None
        else row.recorded_at,
    )


# ── PostgreSQL EventStore ──────────────────────────────────────────────────


class PostgreSQLEventStore:
    """Production EventStore backed by PostgreSQL.

    Injects AsyncSession — session lifecycle owned by UnitOfWork or caller.
    The store participates in the caller's transaction: commit/rollback is
    the caller's responsibility.

    Usage in application service::

        async with uow as uow:
            stored = await event_store.append(batch)
            await uow.commit()
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def append(self, batch: EventBatch) -> Sequence[EventEnvelope]:
        """Append events atomically. Raises OptimisticConcurrencyError on conflict."""
        stream_id = batch.stream_id
        org_id = batch.organization_id
        now = _utc_now()

        # Check expected version vs current version (within transaction)
        current_version = await self._current_stream_version(stream_id)
        if (
            batch.expected_stream_version is not None
            and batch.expected_stream_version != current_version
        ):
            raise OptimisticConcurrencyError(
                stream_id=stream_id,
                expected_version=batch.expected_stream_version,
                actual_version=current_version,
            )

        stored: list[EventEnvelope] = []
        next_stream_pos = current_version + 1

        for ev in batch.events:
            # Allocate next global position from sequence
            global_pos_result = await self._session.execute(
                text("SELECT nextval('platform_events_global_pos_seq')")
            )
            global_pos = int(global_pos_result.scalar_one())

            model = PlatformEventModel(
                global_position=global_pos,
                stream_id=stream_id,
                stream_position=next_stream_pos,
                event_id=ev.event_id,
                event_type=ev.event_type,
                aggregate_type=ev.aggregate_type,
                aggregate_id=ev.aggregate_id,
                organization_id=org_id,
                payload=_serialize_payload(ev.payload),
                metadata_=_serialize_metadata(ev.metadata),
                occurred_at=ev.occurred_at,
                recorded_at=now,
            )
            try:
                self._session.add(model)
                await self._session.flush()
            except IntegrityError as exc:
                await self._session.rollback()
                if "uq_platform_events_stream" in str(exc) or "ix_pe" in str(exc):
                    raise OptimisticConcurrencyError(
                        stream_id=stream_id,
                        expected_version=next_stream_pos,
                        actual_version=next_stream_pos - 1,
                    ) from exc
                if "uq_platform_events" in str(exc.orig if hasattr(exc, "orig") else exc):
                    raise DuplicateEventError(ev.event_id) from exc
                raise

            stored_ev = EventEnvelope(
                event_id=ev.event_id,
                stream_id=stream_id,
                stream_position=next_stream_pos,
                global_position=global_pos,
                event_type=ev.event_type,
                aggregate_type=ev.aggregate_type,
                aggregate_id=ev.aggregate_id,
                organization_id=org_id,
                payload=ev.payload,
                metadata=ev.metadata,
                occurred_at=ev.occurred_at,
                recorded_at=now,
            )
            stored.append(stored_ev)
            next_stream_pos += 1

        return stored

    async def _current_stream_version(self, stream_id: str) -> int:
        """Return max stream_position for stream_id, or -1 if stream is empty."""
        result = await self._session.execute(
            select(func.max(PlatformEventModel.stream_position)).where(
                PlatformEventModel.stream_id == stream_id
            )
        )
        value = result.scalar_one_or_none()
        return int(value) if value is not None else -1

    async def read_stream(
        self,
        stream_id: str,
        organization_id: str,
        from_position: int = 0,
        max_count: int | None = None,
    ) -> Sequence[EventEnvelope]:
        stmt = (
            select(PlatformEventModel)
            .where(
                PlatformEventModel.stream_id == stream_id,
                PlatformEventModel.stream_position >= from_position,
            )
            .order_by(PlatformEventModel.stream_position)
        )
        if max_count is not None:
            stmt = stmt.limit(max_count)

        result = await self._session.execute(stmt)
        rows = result.scalars().all()

        if not rows:
            raise StreamNotFoundError(stream_id)

        for row in rows:
            if row.organization_id != organization_id:
                raise MultiTenantViolationError(organization_id, row.organization_id)

        return [_model_to_envelope(r) for r in rows]

    async def read_all(
        self,
        organization_id: str,
        from_global_position: int = 0,
        max_count: int | None = None,
    ) -> Sequence[EventEnvelope]:
        stmt = (
            select(PlatformEventModel)
            .where(
                PlatformEventModel.organization_id == organization_id,
                PlatformEventModel.global_position >= from_global_position,
            )
            .order_by(PlatformEventModel.global_position)
        )
        if max_count is not None:
            stmt = stmt.limit(max_count)

        result = await self._session.execute(stmt)
        return [_model_to_envelope(r) for r in result.scalars().all()]

    async def stream_version(self, stream_id: str, organization_id: str) -> int:
        return await self._current_stream_version(stream_id)

    async def event_count(self, organization_id: str) -> int:
        result = await self._session.execute(
            select(func.count()).select_from(PlatformEventModel).where(
                PlatformEventModel.organization_id == organization_id
            )
        )
        return int(result.scalar_one())

    async def stream_ids(self, organization_id: str) -> Sequence[str]:
        result = await self._session.execute(
            select(PlatformEventModel.stream_id)
            .where(PlatformEventModel.organization_id == organization_id)
            .distinct()
            .order_by(PlatformEventModel.stream_id)
        )
        return [row[0] for row in result.all()]

    async def read_by_correlation_id(
        self,
        correlation_id: str,
        organization_id: str,
    ) -> Sequence[EventEnvelope]:
        # Use JSONB operator for correlation_id inside metadata column
        stmt = (
            select(PlatformEventModel)
            .where(
                PlatformEventModel.organization_id == organization_id,
                PlatformEventModel.metadata_["correlation_id"].as_string() == correlation_id,
            )
            .order_by(PlatformEventModel.global_position)
        )
        result = await self._session.execute(stmt)
        return [_model_to_envelope(r) for r in result.scalars().all()]

    async def read_by_event_type(
        self,
        event_type: str,
        organization_id: str,
        from_global_position: int = 0,
        max_count: int | None = None,
    ) -> Sequence[EventEnvelope]:
        stmt = (
            select(PlatformEventModel)
            .where(
                PlatformEventModel.organization_id == organization_id,
                PlatformEventModel.event_type == event_type,
                PlatformEventModel.global_position >= from_global_position,
            )
            .order_by(PlatformEventModel.global_position)
        )
        if max_count is not None:
            stmt = stmt.limit(max_count)
        result = await self._session.execute(stmt)
        return [_model_to_envelope(r) for r in result.scalars().all()]

    async def read_by_time_range(
        self,
        organization_id: str,
        from_dt: object,
        to_dt: object,
        max_count: int | None = None,
    ) -> Sequence[EventEnvelope]:
        stmt = (
            select(PlatformEventModel)
            .where(
                PlatformEventModel.organization_id == organization_id,
                PlatformEventModel.occurred_at >= from_dt,
                PlatformEventModel.occurred_at <= to_dt,
            )
            .order_by(PlatformEventModel.global_position)
        )
        if max_count is not None:
            stmt = stmt.limit(max_count)
        result = await self._session.execute(stmt)
        return [_model_to_envelope(r) for r in result.scalars().all()]

    async def read_by_aggregate(
        self,
        aggregate_type: str,
        aggregate_id: str,
        organization_id: str,
        from_stream_position: int = 0,
    ) -> Sequence[EventEnvelope]:
        """Read all events for a specific aggregate (for rehydration)."""
        stream_id = f"{aggregate_type}:{aggregate_id}"
        stmt = (
            select(PlatformEventModel)
            .where(
                PlatformEventModel.stream_id == stream_id,
                PlatformEventModel.organization_id == organization_id,
                PlatformEventModel.stream_position >= from_stream_position,
            )
            .order_by(PlatformEventModel.stream_position)
        )
        result = await self._session.execute(stmt)
        return [_model_to_envelope(r) for r in result.scalars().all()]

    async def fetch_by_event_id(self, event_id: str) -> EventEnvelope | None:
        """Fetch a single event by its unique event_id (for DLQ replay).

        The event_id column has a unique constraint so at most one row
        can match. No organization_id filter — callers must verify tenant
        context from TenantContext before acting on the result.

        Args:
            event_id: The unique event identifier assigned at append time.

        Returns:
            The EventEnvelope, or None if the event has been purged or never existed.
        """
        result = await self._session.execute(
            select(PlatformEventModel).where(
                PlatformEventModel.event_id == event_id
            )
        )
        row = result.scalars().first()
        return _model_to_envelope(row) if row is not None else None

    async def tombstone(
        self,
        stream_id: str,
        event_id: str,
        organization_id: str,
    ) -> None:
        """GDPR right-to-erasure (DEBT-S26).

        Replaces the payload of an event with a redaction marker in-place.
        The tombstone row remains so that stream positions stay contiguous
        and projections can detect the erasure. Organization ownership is
        verified before erasure to prevent cross-tenant data deletion.

        Raises:
            ValueError: if the event does not belong to organization_id.
        """
        result = await self._session.execute(
            select(PlatformEventModel).where(
                PlatformEventModel.event_id == event_id,
                PlatformEventModel.stream_id == stream_id,
            )
        )
        row = result.scalars().first()
        if row is None:
            return  # idempotent — already erased or never existed
        if row.organization_id != organization_id:
            raise ValueError(
                f"tombstone cross-tenant rejected: "
                f"event {event_id!r} belongs to {row.organization_id!r}, "
                f"not {organization_id!r}"
            )
        await self._session.execute(
            update(PlatformEventModel)
            .where(PlatformEventModel.event_id == event_id)
            .values(payload={"_tombstoned": True, "reason": "gdpr_erasure"})
        )
