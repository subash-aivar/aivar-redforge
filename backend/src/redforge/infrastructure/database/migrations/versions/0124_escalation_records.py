"""0124 — M35 migration.

Migration chain: 0123 → 0124.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0124"
down_revision: str = "0123"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.create_table(
        "escalation_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("execution_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("step_number", sa.Integer(), nullable=False),
        sa.Column("impact_level", sa.String(20), nullable=False),
        sa.Column("required_role", sa.String(50), nullable=False),
        sa.Column("trigger_operator_id", sa.Text(), nullable=False),
        sa.Column("escalated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("authorized_by", sa.Text(), nullable=True),
        sa.Column("authorized_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolution", sa.String(20), nullable=True),
        schema="automated_action",
    )
    op.create_index(
        "ix_escalation_execution", "escalation_records", ["execution_id"], schema="automated_action"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_escalation_pending "
        "ON automated_action.escalation_records (tenant_id, resolution) "
        "WHERE resolution IS NULL"
    )


def downgrade() -> None:

    op.execute("DROP INDEX IF EXISTS automated_action.ix_escalation_pending")
    op.drop_index(
        "ix_escalation_execution", table_name="escalation_records", schema="automated_action"
    )
    op.drop_table("escalation_records", schema="automated_action")
