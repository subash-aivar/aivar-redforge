"""SQLAlchemy ORM models for the Platform event store — Sprint 25.

These models exist for two purposes:
1. Alembic schema generation — Alembic reads these models to produce migrations.
2. Type-safe column definitions — column types are defined once here.

The PostgreSQL implementations in event_store.py, snapshot_store.py, and
checkpoint_repository.py use these models for type-checked queries.

Design rules:
- Models are thin schema declarations — zero business logic.
- All JSONB columns store dict payloads for schema flexibility.
- Indexes are declared here and enforced at database level.
- SQLAlchemy 2.x Mapped[] syntax throughout.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, BigInteger, Index, Integer, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base

# JSONB on PostgreSQL (production), plain JSON on any other dialect. This is
# the codebase's established idiom (see models/campaign_result.py) and is
# what lets a SQLite-backed unit/integration test do
# `Base.metadata.create_all()` over the full metadata without the SQLite
# type compiler choking on a Postgres-only JSONB column — the effective
# production type is unchanged (JSONB), the migrations (0007) are unchanged.
_JSONB_PORTABLE = JSON().with_variant(JSONB, "postgresql")


class PlatformEventModel(Base):
    """Append-only event log row.

    One row = one EventEnvelope. Immutable after insert.

    global_position: monotonically increasing sequence across ALL streams,
        assigned by PostgreSQL BIGSERIAL. Used for projection catch-up.
    stream_position: monotonically increasing within a stream. The
        UNIQUE(stream_id, stream_position) constraint acts as the
        optimistic concurrency guard — a duplicate position insert
        raises IntegrityError → translated to OptimisticConcurrencyError.
    event_id: globally unique ULID for deduplication and idempotency.
    payload: opaque JSONB blob. The bounded context owns its schema.
    metadata: JSONB containing correlation_id, causation_id, schema_version,
        actor_id, actor_type, source_service, and custom key-value pairs.
    """

    __tablename__ = "platform_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    global_position: Mapped[int] = mapped_column(BigInteger, nullable=False, unique=True)
    stream_id: Mapped[str] = mapped_column(Text, nullable=False)
    stream_position: Mapped[int] = mapped_column(Integer, nullable=False)
    event_id: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    aggregate_type: Mapped[str] = mapped_column(Text, nullable=False)
    aggregate_id: Mapped[str] = mapped_column(Text, nullable=False)
    organization_id: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", _JSONB_PORTABLE, nullable=False
    )
    occurred_at: Mapped[datetime] = mapped_column(nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(nullable=False)

    __table_args__ = (
        # OCC guard: stream_id + stream_position must be unique
        UniqueConstraint("stream_id", "stream_position", name="uq_platform_events_stream"),
        # Fast org-scoped global-position queries (used by catch-up)
        Index("ix_pe_org_global", "organization_id", "global_position"),
        # Fast event-type queries (used by replay_by_event_type)
        Index("ix_pe_org_event_type_global", "organization_id", "event_type", "global_position"),
        # Fast aggregate replay (used by AggregateRehydrationRepository)
        Index("ix_pe_aggregate", "aggregate_type", "aggregate_id", "organization_id",
              "stream_position"),
        # Fast time-range queries (used by replay_by_time_range)
        Index("ix_pe_org_occurred_at", "organization_id", "occurred_at"),
    )


class PlatformSnapshotModel(Base):
    """Aggregate state snapshot row.

    Snapshots accelerate aggregate rehydration for long-lived streams.
    Multiple snapshots per aggregate are kept (for audit); the latest
    is selected by MAX(global_position_at_snapshot).

    state: opaque JSONB dict produced by aggregate.to_snapshot_state().
    schema_version: '1.0' format string. Used by VersionResolver on load.
    """

    __tablename__ = "platform_snapshots"

    snapshot_id: Mapped[str] = mapped_column(Text, primary_key=True)
    aggregate_type: Mapped[str] = mapped_column(Text, nullable=False)
    aggregate_id: Mapped[str] = mapped_column(Text, nullable=False)
    organization_id: Mapped[str] = mapped_column(Text, nullable=False)
    state: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    stream_version_at_snapshot: Mapped[int] = mapped_column(Integer, nullable=False)
    global_position_at_snapshot: Mapped[int] = mapped_column(BigInteger, nullable=False)
    schema_version: Mapped[str] = mapped_column(Text, nullable=False, default="1.0")
    created_at: Mapped[datetime] = mapped_column(nullable=False)

    __table_args__ = (
        # Fast latest-snapshot lookup (ORDER BY global_position DESC LIMIT 1)
        Index(
            "ix_ps_latest",
            "aggregate_type", "aggregate_id", "organization_id",
            "global_position_at_snapshot",
        ),
    )


class PlatformCheckpointModel(Base):
    """Projection checkpoint row.

    One row per projection. UPSERT on projection_id.

    last_global_position: The global_position of the last successfully
        processed event. On restart, the IdempotentProjectionEngine skips
        all events at position <= last_global_position.
    events_processed: Running counter for observability only (not used
        for idempotency — position is the canonical signal).
    """

    __tablename__ = "platform_checkpoints"

    projection_id: Mapped[str] = mapped_column(Text, primary_key=True)
    projection_name: Mapped[str] = mapped_column(Text, nullable=False)
    last_global_position: Mapped[int] = mapped_column(BigInteger, nullable=False, default=-1)
    last_processed_at: Mapped[datetime] = mapped_column(nullable=False)
    state: Mapped[str] = mapped_column(Text, nullable=False, default="live")
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    events_processed: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(nullable=False)


class PlatformReadModelModel(Base):
    """Generic JSONB read model store.

    One row per (model_type, organization_id). UPSERT on primary key.

    data: the full ReadModel subclass serialised to dict.
    """

    __tablename__ = "platform_read_models"

    model_type: Mapped[str] = mapped_column(Text, primary_key=True)
    organization_id: Mapped[str] = mapped_column(Text, primary_key=True)
    data: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    last_updated_at: Mapped[datetime] = mapped_column(nullable=False)
    last_event_position: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)


class DeadLetterEntryModel(Base):
    """Persistent dead letter queue entry — Sprint 28/31.

    Status lifecycle (Sprint 31):
        pending → requeued → in_flight → (success) deleted
                                       → (failure) requeued
                                       → (retries exhausted) exhausted

    reserved_until: set when a worker claims the entry; NULL otherwise.
        Expired reservations (reserved_until < NOW()) are re-claimable.
    exhausted_at: set when retry_count exceeds threshold. Terminal state.
    version: optimistic concurrency control — incremented on every UPDATE.
    """

    __tablename__ = "dead_letter_entries"

    entry_id: Mapped[str] = mapped_column(Text, primary_key=True)
    source_projection: Mapped[str] = mapped_column(Text, nullable=False)
    event_id: Mapped[str] = mapped_column(Text, nullable=False)
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    error_message: Mapped[str] = mapped_column(Text, nullable=False)
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="pending")
    first_failed_at: Mapped[datetime] = mapped_column(nullable=False)
    last_failed_at: Mapped[datetime] = mapped_column(nullable=False)
    organization_id: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(nullable=False)
    updated_at: Mapped[datetime] = mapped_column(nullable=False)
    reserved_until: Mapped[datetime | None] = mapped_column(nullable=True)
    exhausted_at: Mapped[datetime | None] = mapped_column(nullable=True)

    __table_args__ = (
        Index("ix_dle_org_status", "organization_id", "status"),
        Index("ix_dle_org_projection", "organization_id", "source_projection"),
        Index("ix_dle_event_id", "event_id"),
    )
