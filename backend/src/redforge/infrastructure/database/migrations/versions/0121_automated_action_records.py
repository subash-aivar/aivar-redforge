"""0121 — M35 migration.

Migration chain: 0120 → 0121.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0121"
down_revision: str = "0120"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.create_table(
        "automated_action_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("execution_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("step_number", sa.Integer(), nullable=False),
        sa.Column("action_type", sa.Text(), nullable=False),
        sa.Column("connector_type", sa.String(50), nullable=False),
        sa.Column("target_resource", sa.Text(), nullable=False),
        sa.Column("parameters_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("outcome", sa.String(20), nullable=True),
        sa.Column("external_reference", sa.Text(), nullable=True),
        sa.Column("failure_mode", sa.String(40), nullable=True),
        sa.Column("attempted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("rollback_available", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("rollback_parameters_ref", sa.Text(), nullable=True),
        schema="automated_action",
    )
    op.create_index(
        "ix_aar_execution", "automated_action_records", ["execution_id"], schema="automated_action"
    )
    op.create_index(
        "ix_aar_tenant_connector",
        "automated_action_records",
        ["tenant_id", "connector_type"],
        schema="automated_action",
    )
    op.create_index(
        "ix_aar_tenant_attempted",
        "automated_action_records",
        ["tenant_id", "attempted_at"],
        schema="automated_action",
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_aar_pending_attempted "
        "ON automated_action.automated_action_records (status, attempted_at) "
        "WHERE status = 'PENDING'"
    )


def downgrade() -> None:

    op.execute("DROP INDEX IF EXISTS automated_action.ix_aar_pending_attempted")
    op.drop_index(
        "ix_aar_tenant_attempted", table_name="automated_action_records", schema="automated_action"
    )
    op.drop_index(
        "ix_aar_tenant_connector", table_name="automated_action_records", schema="automated_action"
    )
    op.drop_index(
        "ix_aar_execution", table_name="automated_action_records", schema="automated_action"
    )
    op.drop_table("automated_action_records", schema="automated_action")
