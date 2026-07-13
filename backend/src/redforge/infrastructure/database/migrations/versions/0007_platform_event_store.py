"""Create platform event store tables — Sprint 25.

Creates four tables for the Enterprise Persistence & Reliability Platform:

  platform_events       — append-only event log (one row per EventEnvelope)
  platform_snapshots    — aggregate state snapshots (for rehydration optimisation)
  platform_checkpoints  — projection checkpoints (for crash recovery)
  platform_read_models  — generic JSONB read model store

Also creates the dedicated global position sequence used by the event store to
assign monotonically-increasing global_position values across all streams.

The UNIQUE constraint on (stream_id, stream_position) is the optimistic
concurrency guard: a concurrent writer trying to insert at the same
stream_position receives a unique_violation IntegrityError, which the
PostgreSQL EventStore translates to OptimisticConcurrencyError.

Revision ID: 0007
Revises: 0006
Create Date: 2026-07-10 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Dedicated sequence for global_position — separate from the table PK
    # so the global ordering remains stable even if rows are later soft-deleted
    # (which they should not be, but defensive design).
    op.execute(
        "CREATE SEQUENCE IF NOT EXISTS platform_events_global_pos_seq "
        "START WITH 1 INCREMENT BY 1 NO MINVALUE NO MAXVALUE CACHE 1"
    )

    # ── platform_events ─────────────────────────────────────────────────
    op.create_table(
        "platform_events",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column(
            "global_position",
            sa.BigInteger,
            nullable=False,
            unique=True,
            comment="Monotonic across all streams. Assigned by sequence.",
        ),
        sa.Column("stream_id", sa.Text, nullable=False),
        sa.Column(
            "stream_position",
            sa.Integer,
            nullable=False,
            comment="Monotonic within stream. UNIQUE with stream_id = OCC guard.",
        ),
        sa.Column("event_id", sa.Text, nullable=False),
        sa.Column("event_type", sa.Text, nullable=False),
        sa.Column("aggregate_type", sa.Text, nullable=False),
        sa.Column("aggregate_id", sa.Text, nullable=False),
        sa.Column("organization_id", sa.Text, nullable=False),
        sa.Column("payload", sa.dialects.postgresql.JSONB, nullable=False),
        sa.Column("metadata", sa.dialects.postgresql.JSONB, nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    # OCC guard: unique (stream_id, stream_position) prevents double-writes
    op.create_unique_constraint(
        "uq_platform_events_stream",
        "platform_events",
        ["stream_id", "stream_position"],
    )
    # Dedup guard: event_id is globally unique
    op.create_unique_constraint(
        "uq_platform_events_event_id",
        "platform_events",
        ["event_id"],
    )

    # Indexes for common query patterns
    op.create_index(
        "ix_pe_org_global",
        "platform_events",
        ["organization_id", "global_position"],
    )
    op.create_index(
        "ix_pe_org_event_type_global",
        "platform_events",
        ["organization_id", "event_type", "global_position"],
    )
    op.create_index(
        "ix_pe_aggregate",
        "platform_events",
        ["aggregate_type", "aggregate_id", "organization_id", "stream_position"],
    )
    op.create_index(
        "ix_pe_org_occurred_at",
        "platform_events",
        ["organization_id", "occurred_at"],
    )

    # ── platform_snapshots ───────────────────────────────────────────────
    op.create_table(
        "platform_snapshots",
        sa.Column("snapshot_id", sa.Text, primary_key=True),
        sa.Column("aggregate_type", sa.Text, nullable=False),
        sa.Column("aggregate_id", sa.Text, nullable=False),
        sa.Column("organization_id", sa.Text, nullable=False),
        sa.Column("state", sa.dialects.postgresql.JSONB, nullable=False),
        sa.Column("stream_version_at_snapshot", sa.Integer, nullable=False),
        sa.Column("global_position_at_snapshot", sa.BigInteger, nullable=False),
        sa.Column("schema_version", sa.Text, nullable=False, server_default="1.0"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "ix_ps_latest",
        "platform_snapshots",
        ["aggregate_type", "aggregate_id", "organization_id", "global_position_at_snapshot"],
    )

    # ── platform_checkpoints ─────────────────────────────────────────────
    op.create_table(
        "platform_checkpoints",
        sa.Column(
            "projection_id",
            sa.Text,
            primary_key=True,
            comment="projection_name used as projection_id for simplicity",
        ),
        sa.Column("projection_name", sa.Text, nullable=False),
        sa.Column(
            "last_global_position",
            sa.BigInteger,
            nullable=False,
            server_default="-1",
            comment="Events at position <= this value have been processed.",
        ),
        sa.Column("last_processed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("state", sa.Text, nullable=False, server_default="live"),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("events_processed", sa.BigInteger, nullable=False, server_default="0"),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    # ── platform_read_models ─────────────────────────────────────────────
    op.create_table(
        "platform_read_models",
        sa.Column("model_type", sa.Text, primary_key=True),
        sa.Column("organization_id", sa.Text, primary_key=True),
        sa.Column("data", sa.dialects.postgresql.JSONB, nullable=False),
        sa.Column("last_updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_event_position", sa.BigInteger, nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_table("platform_read_models")
    op.drop_table("platform_checkpoints")
    op.drop_index("ix_ps_latest", table_name="platform_snapshots")
    op.drop_table("platform_snapshots")
    op.drop_index("ix_pe_org_occurred_at", table_name="platform_events")
    op.drop_index("ix_pe_aggregate", table_name="platform_events")
    op.drop_index("ix_pe_org_event_type_global", table_name="platform_events")
    op.drop_index("ix_pe_org_global", table_name="platform_events")
    op.drop_constraint("uq_platform_events_event_id", "platform_events", type_="unique")
    op.drop_constraint("uq_platform_events_stream", "platform_events", type_="unique")
    op.drop_table("platform_events")
    op.execute("DROP SEQUENCE IF EXISTS platform_events_global_pos_seq")
