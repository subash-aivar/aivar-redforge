"""0051 — M26 Phase 6 Cloud Runtime Visibility tables.

cloud_runtime_events is PARTITION BY RANGE (event_time) with monthly
partitions for current month ±1 and a DEFAULT partition. Unique dedup key
includes event_time (required for PostgreSQL partitioned unique indexes).
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0051"
down_revision: str = "0050"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_SCHEMA = "cloud_security"


def _month_bounds(year: int, month: int) -> tuple[str, str]:
    start = datetime(year, month, 1, tzinfo=UTC)
    if month == 12:
        end = datetime(year + 1, 1, 1, tzinfo=UTC)
    else:
        end = datetime(year, month + 1, 1, tzinfo=UTC)
    return start.date().isoformat(), end.date().isoformat()


def upgrade() -> None:
    # Partitioned parent — PK/unique must include partition key (event_time).
    op.execute(
        sa.text(
            f"""
            CREATE TABLE {_SCHEMA}.cloud_runtime_events (
                id UUID NOT NULL,
                organization_id VARCHAR(26) NOT NULL,
                cloud_account_id UUID NOT NULL,
                event_type VARCHAR(64) NOT NULL,
                source VARCHAR(64) NOT NULL,
                severity VARCHAR(32) NOT NULL,
                outcome VARCHAR(32) NOT NULL,
                event_time TIMESTAMPTZ NOT NULL,
                ingested_at TIMESTAMPTZ NOT NULL,
                provider_event_id VARCHAR(512) NOT NULL,
                identity JSONB NOT NULL,
                host JSONB NOT NULL,
                container JSONB NOT NULL,
                metadata JSONB NOT NULL,
                correlation_refs JSONB NOT NULL,
                correlation_links JSONB NOT NULL,
                artifacts JSONB NOT NULL,
                evidence JSONB NOT NULL,
                raw_payload JSONB NOT NULL,
                source_ip VARCHAR(128) NOT NULL DEFAULT '',
                target_resource VARCHAR(512) NOT NULL DEFAULT '',
                created_at TIMESTAMPTZ NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL,
                row_version INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (id, event_time),
                CONSTRAINT uq_cloud_runtime_events_org_source_provider
                    UNIQUE (organization_id, source, provider_event_id, event_time)
            ) PARTITION BY RANGE (event_time)
            """
        )
    )
    op.execute(
        sa.text(
            f"CREATE INDEX ix_cloud_runtime_events_org_event_time "
            f"ON {_SCHEMA}.cloud_runtime_events (organization_id, event_time)"
        )
    )
    op.execute(
        sa.text(
            f"CREATE INDEX ix_cloud_runtime_events_account_event_time "
            f"ON {_SCHEMA}.cloud_runtime_events (cloud_account_id, event_time)"
        )
    )
    op.execute(
        sa.text(
            f"CREATE INDEX ix_cloud_runtime_events_event_type "
            f"ON {_SCHEMA}.cloud_runtime_events (event_type)"
        )
    )
    op.execute(
        sa.text(
            f"CREATE INDEX ix_cloud_runtime_events_source "
            f"ON {_SCHEMA}.cloud_runtime_events (source)"
        )
    )
    op.execute(
        sa.text(
            f"CREATE INDEX ix_cloud_runtime_events_organization_id "
            f"ON {_SCHEMA}.cloud_runtime_events (organization_id)"
        )
    )

    # Current month ±1 (relative to migration apply time) + DEFAULT catch-all.
    now = datetime.now(UTC)
    months: list[tuple[int, int]] = []
    y, m = now.year, now.month
    for delta in (-1, 0, 1):
        mm = m + delta
        yy = y
        if mm < 1:
            mm += 12
            yy -= 1
        elif mm > 12:
            mm -= 12
            yy += 1
        months.append((yy, mm))

    for yy, mm in months:
        start, end = _month_bounds(yy, mm)
        part = f"cloud_runtime_events_y{yy}m{mm:02d}"
        op.execute(
            sa.text(
                f"CREATE TABLE {_SCHEMA}.{part} "
                f"PARTITION OF {_SCHEMA}.cloud_runtime_events "
                f"FOR VALUES FROM ('{start}') TO ('{end}')"
            )
        )
    op.execute(
        sa.text(
            f"CREATE TABLE {_SCHEMA}.cloud_runtime_events_default "
            f"PARTITION OF {_SCHEMA}.cloud_runtime_events DEFAULT"
        )
    )

    op.create_table(
        "runtime_processes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", sa.String(length=26), nullable=False),
        sa.Column("runtime_event_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("process_name", sa.String(length=256), nullable=False),
        sa.Column("executable_path", sa.String(length=1024), nullable=False),
        sa.Column("pid", sa.Integer(), nullable=True),
        sa.Column("parent_pid", sa.Integer(), nullable=True),
        sa.Column("command_line", sa.String(length=4096), nullable=False),
        sa.Column("user_name", sa.String(length=256), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_runtime_processes_organization_id",
        "runtime_processes",
        ["organization_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_runtime_processes_runtime_event_id",
        "runtime_processes",
        ["runtime_event_id"],
        schema=_SCHEMA,
    )

    op.create_table(
        "runtime_network_connections",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", sa.String(length=26), nullable=False),
        sa.Column("runtime_event_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("direction", sa.String(length=32), nullable=False),
        sa.Column("protocol", sa.String(length=32), nullable=False),
        sa.Column("local_address", sa.String(length=128), nullable=False),
        sa.Column("local_port", sa.Integer(), nullable=True),
        sa.Column("remote_address", sa.String(length=128), nullable=False),
        sa.Column("remote_port", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_runtime_network_connections_organization_id",
        "runtime_network_connections",
        ["organization_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_runtime_network_connections_runtime_event_id",
        "runtime_network_connections",
        ["runtime_event_id"],
        schema=_SCHEMA,
    )

    op.create_table(
        "runtime_file_activities",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", sa.String(length=26), nullable=False),
        sa.Column("runtime_event_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("operation", sa.String(length=64), nullable=False),
        sa.Column("path", sa.String(length=2048), nullable=False),
        sa.Column("file_hash", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_runtime_file_activities_organization_id",
        "runtime_file_activities",
        ["organization_id"],
        schema=_SCHEMA,
    )

    op.create_table(
        "runtime_identity_sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", sa.String(length=26), nullable=False),
        sa.Column("runtime_event_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("identity", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("session_id", sa.String(length=256), nullable=False),
        sa.Column("mfa_used", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("source_ip", sa.String(length=128), nullable=False),
        sa.Column("user_agent", sa.String(length=512), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_runtime_identity_sessions_organization_id",
        "runtime_identity_sessions",
        ["organization_id"],
        schema=_SCHEMA,
    )

    op.create_table(
        "runtime_execution_contexts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", sa.String(length=26), nullable=False),
        sa.Column("runtime_event_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("process_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("container_id", sa.String(length=128), nullable=False),
        sa.Column("host_id", sa.String(length=128), nullable=False),
        sa.Column("workload_ref", sa.String(length=256), nullable=False),
        sa.Column("environment", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_runtime_execution_contexts_organization_id",
        "runtime_execution_contexts",
        ["organization_id"],
        schema=_SCHEMA,
    )

    op.create_table(
        "runtime_artifacts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", sa.String(length=26), nullable=False),
        sa.Column("runtime_event_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("artifact_id", sa.String(length=128), nullable=False),
        sa.Column("artifact_type", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=512), nullable=False),
        sa.Column("digest", sa.String(length=256), nullable=False),
        sa.Column("path", sa.String(length=2048), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_runtime_artifacts_organization_id",
        "runtime_artifacts",
        ["organization_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_runtime_artifacts_runtime_event_id",
        "runtime_artifacts",
        ["runtime_event_id"],
        schema=_SCHEMA,
    )


def downgrade() -> None:
    op.drop_table("runtime_artifacts", schema=_SCHEMA)
    op.drop_table("runtime_execution_contexts", schema=_SCHEMA)
    op.drop_table("runtime_identity_sessions", schema=_SCHEMA)
    op.drop_table("runtime_file_activities", schema=_SCHEMA)
    op.drop_table("runtime_network_connections", schema=_SCHEMA)
    op.drop_table("runtime_processes", schema=_SCHEMA)
    # CASCADE drops all partitions of the parent.
    op.execute(sa.text(f"DROP TABLE IF EXISTS {_SCHEMA}.cloud_runtime_events CASCADE"))
