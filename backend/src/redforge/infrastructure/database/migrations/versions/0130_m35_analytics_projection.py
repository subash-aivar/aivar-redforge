"""0130 — M35 migration.

Migration chain: 0129 → 0130.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0130"
down_revision: str = "0129"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.execute("CREATE SCHEMA IF NOT EXISTS analytics")
    op.create_table(
        "automation_events",
        sa.Column("event_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("execution_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("event_type", sa.String(80), nullable=False),
        sa.Column("playbook_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("outcome", sa.String(40), nullable=True),
        sa.Column("action_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("event_ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        schema="analytics",
    )
    op.create_index(
        "ix_automation_events_tenant_ts",
        "automation_events",
        ["tenant_id", "event_ts"],
        schema="analytics",
    )
    op.create_index(
        "ix_automation_events_tenant_pb_ts",
        "automation_events",
        ["tenant_id", "playbook_id", "event_ts"],
        schema="analytics",
    )


def downgrade() -> None:

    op.drop_index(
        "ix_automation_events_tenant_pb_ts", table_name="automation_events", schema="analytics"
    )
    op.drop_index(
        "ix_automation_events_tenant_ts", table_name="automation_events", schema="analytics"
    )
    op.drop_table("automation_events", schema="analytics")
