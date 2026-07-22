"""0120 — M35 migration.

Migration chain: 0119 → 0120.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0120"
down_revision: str = "0119"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.execute("CREATE SCHEMA IF NOT EXISTS automated_action")
    op.create_table(
        "automation_executions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("playbook_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("playbook_version", sa.Integer(), nullable=False),
        sa.Column("playbook_content_hash", sa.String(64), nullable=False),
        sa.Column("trigger_source_context", sa.String(40), nullable=False),
        sa.Column("source_event_id", sa.Text(), nullable=False),
        sa.Column("status", sa.String(40), nullable=False),
        sa.Column("operator_id", sa.Text(), nullable=False),
        sa.Column("current_step", sa.Integer(), nullable=False),
        sa.Column("total_steps", sa.Integer(), nullable=False),
        sa.Column("max_impact_level", sa.String(20), nullable=False),
        sa.Column("escalation_request", postgresql.JSONB(), nullable=True),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        schema="automated_action",
    )
    op.create_index(
        "ix_auto_exec_tenant_pb",
        "automation_executions",
        ["tenant_id", "playbook_id"],
        schema="automated_action",
    )
    op.create_index(
        "ix_auto_exec_tenant_status",
        "automation_executions",
        ["tenant_id", "status"],
        schema="automated_action",
    )
    op.create_index(
        "ix_auto_exec_tenant_created",
        "automation_executions",
        ["tenant_id", "created_at"],
        schema="automated_action",
    )
    op.create_index(
        "ix_auto_exec_source_event",
        "automation_executions",
        ["source_event_id"],
        schema="automated_action",
    )


def downgrade() -> None:

    op.drop_index(
        "ix_auto_exec_source_event", table_name="automation_executions", schema="automated_action"
    )
    op.drop_index(
        "ix_auto_exec_tenant_created", table_name="automation_executions", schema="automated_action"
    )
    op.drop_index(
        "ix_auto_exec_tenant_status", table_name="automation_executions", schema="automated_action"
    )
    op.drop_index(
        "ix_auto_exec_tenant_pb", table_name="automation_executions", schema="automated_action"
    )
    op.drop_table("automation_executions", schema="automated_action")
    op.execute("DROP SCHEMA IF EXISTS automated_action CASCADE")
