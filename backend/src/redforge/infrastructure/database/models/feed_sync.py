"""SQLAlchemy ORM models for the Feed Synchronization Foundation
sub-context — M22 Phase 2.

Two tables, both created in migration `0036`:

  - `feeds` — durable configuration + lifecycle state for one
    schedulable threat-intel source. GLOBAL (no `organization_id`) or
    TENANT-scoped, mirroring the exact `scope` discriminator
    `StixIngestionLogModel` (M22 Phase 1) already established.
  - `feed_sync_runs` — execution-history rows for `feeds`, one per
    synchronization attempt.

Pure persistence mapping — no business logic. Aggregate <-> row
translation lives in `infrastructure.database.repositories.feed_sync`.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base


class FeedModel(Base):
    """A configured, schedulable threat-intel feed. GLOBAL feeds carry
    no `organization_id`; TENANT feeds always do — enforced by
    `ck_feeds_scope_org_pairing` (migration 0036)."""

    __tablename__ = "feeds"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    feed_key: Mapped[str] = mapped_column(String(64), nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    source_kind: Mapped[str] = mapped_column(String(30), nullable=False)
    scope: Mapped[str] = mapped_column(String(10), nullable=False, default="GLOBAL")
    organization_id: Mapped[str | None] = mapped_column(String(26), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="draft")
    connector_config: Mapped[dict[str, object]] = mapped_column(
        JSON, nullable=False, default=dict
    )
    credential_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    schedule_interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    retry_max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    retry_base_delay_seconds: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    retry_max_delay_seconds: Mapped[float] = mapped_column(Float, nullable=False, default=30.0)
    retry_jitter_factor: Mapped[float] = mapped_column(Float, nullable=False, default=0.25)
    checkpoint: Mapped[str | None] = mapped_column(Text, nullable=True)
    consecutive_failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_sync_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_sync_completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_sync_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    next_sync_due_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_by: Mapped[str] = mapped_column(String(26), nullable=False)
    updated_by: Mapped[str] = mapped_column(String(26), nullable=False)


class FeedSyncRunModel(Base):
    """One execution-history row for a `FeedModel` synchronization
    attempt. `ux_fsr_feed_active_run` (migration 0036) enforces at most
    one non-terminal (pending/running) row per `feed_id`."""

    __tablename__ = "feed_sync_runs"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    feed_id: Mapped[str] = mapped_column(
        String(26),
        ForeignKey("feeds.id", name="fk_fsr_feed", ondelete="CASCADE"),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    trigger: Mapped[str] = mapped_column(String(20), nullable=False)
    checkpoint_before: Mapped[str | None] = mapped_column(Text, nullable=True)
    checkpoint_after: Mapped[str | None] = mapped_column(Text, nullable=True)
    items_fetched: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    items_processed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    items_failed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    retry_attempts_used: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str] = mapped_column(String(26), nullable=False)
