"""0067 — M29 Phase 4 execution pipeline foundation.

Creates attack_actions (RANGE partitioned by execution_timestamp with monthly
partitions) and execution_workers. down_revision=0066.
"""

from __future__ import annotations

from calendar import monthrange
from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0067"
down_revision: str = "0066"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_SCHEMA = "execution"


def _month_bounds(year: int, month: int) -> tuple[str, str]:
    start = datetime(year, month, 1, tzinfo=UTC)
    last_day = monthrange(year, month)[1]
    if month == 12:
        end = datetime(year + 1, 1, 1, tzinfo=UTC)
    else:
        end = datetime(year, month + 1, 1, tzinfo=UTC)
    _ = last_day
    return start.isoformat(), end.isoformat()


def upgrade() -> None:
    # Partitioned attack_actions — PK includes partition key (execution_timestamp).
    op.execute(
        sa.text(
            f"""
            CREATE TABLE {_SCHEMA}.attack_actions (
                id UUID NOT NULL,
                execution_timestamp TIMESTAMPTZ NOT NULL,
                tenant_id UUID NOT NULL,
                engagement_id UUID NOT NULL,
                operation_id UUID NOT NULL,
                step_id UUID NOT NULL,
                target_id UUID NOT NULL,
                technique_id VARCHAR(256) NOT NULL,
                technique_category VARCHAR(128) NOT NULL,
                impact_ceiling VARCHAR(32) NOT NULL,
                operator_id UUID NOT NULL,
                worker_id UUID NULL,
                state VARCHAR(32) NOT NULL,
                action_hash VARCHAR(64) NOT NULL,
                input_hash VARCHAR(64) NOT NULL,
                action_input_json JSONB NOT NULL,
                safety_check_json JSONB NOT NULL,
                completion_timestamp TIMESTAMPTZ NULL,
                output_hash VARCHAR(64) NULL,
                output_storage_ref VARCHAR(512) NULL,
                failure_reason TEXT NULL,
                created_at TIMESTAMPTZ NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL,
                row_version INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (id, execution_timestamp)
            ) PARTITION BY RANGE (execution_timestamp)
            """
        )
    )
    op.execute(
        sa.text(
            f"CREATE INDEX ix_attack_actions_tenant_execution "
            f"ON {_SCHEMA}.attack_actions (tenant_id, execution_timestamp)"
        )
    )
    op.execute(
        sa.text(
            f"CREATE INDEX ix_attack_actions_tenant_operation "
            f"ON {_SCHEMA}.attack_actions (tenant_id, operation_id)"
        )
    )
    op.execute(
        sa.text(
            f"CREATE INDEX ix_attack_actions_tenant_engagement "
            f"ON {_SCHEMA}.attack_actions (tenant_id, engagement_id)"
        )
    )
    op.execute(
        sa.text(
            f"CREATE INDEX ix_attack_actions_tenant_step "
            f"ON {_SCHEMA}.attack_actions (tenant_id, step_id)"
        )
    )
    op.execute(
        sa.text(
            f"CREATE INDEX ix_attack_actions_tenant_state "
            f"ON {_SCHEMA}.attack_actions (tenant_id, state)"
        )
    )

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
        part = f"attack_actions_y{yy}m{mm:02d}"
        op.execute(
            sa.text(
                f"CREATE TABLE {_SCHEMA}.{part} "
                f"PARTITION OF {_SCHEMA}.attack_actions "
                f"FOR VALUES FROM ('{start}') TO ('{end}')"
            )
        )
    op.execute(
        sa.text(
            f"CREATE TABLE {_SCHEMA}.attack_actions_default "
            f"PARTITION OF {_SCHEMA}.attack_actions DEFAULT"
        )
    )

    op.create_table(
        "execution_workers",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("worker_type", sa.String(length=64), nullable=False),
        sa.Column("trust_level", sa.String(length=32), nullable=False),
        sa.Column("health_status", sa.String(length=32), nullable=False),
        sa.Column("network_zone", sa.String(length=128), nullable=False),
        sa.Column("capabilities_json", postgresql.JSONB(), nullable=False),
        sa.Column("manifest_hash", sa.String(length=64), nullable=False),
        sa.Column("signer_operator_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("registered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decommissioned_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="0"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_execution_workers_tenant_health",
        "execution_workers",
        ["tenant_id", "health_status"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_execution_workers_tenant_zone",
        "execution_workers",
        ["tenant_id", "network_zone"],
        schema=_SCHEMA,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_execution_workers_tenant_zone",
        table_name="execution_workers",
        schema=_SCHEMA,
    )
    op.drop_index(
        "ix_execution_workers_tenant_health",
        table_name="execution_workers",
        schema=_SCHEMA,
    )
    op.drop_table("execution_workers", schema=_SCHEMA)
    op.execute(sa.text(f"DROP TABLE IF EXISTS {_SCHEMA}.attack_actions CASCADE"))
