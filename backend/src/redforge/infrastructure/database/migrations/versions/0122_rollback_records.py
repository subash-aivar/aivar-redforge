"""0122 — M35 migration.

Migration chain: 0121 → 0122.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0122"
down_revision: str = "0121"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.create_table(
        "rollback_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("original_record_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("execution_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("rollback_status", sa.String(30), nullable=False),
        sa.Column("initiated_by", sa.Text(), nullable=False),
        sa.Column("initiated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        schema="automated_action",
    )
    op.create_index(
        "ix_rollback_execution", "rollback_records", ["execution_id"], schema="automated_action"
    )
    op.create_index(
        "ix_rollback_original",
        "rollback_records",
        ["original_record_id"],
        schema="automated_action",
    )
    op.create_index(
        "ix_rollback_tenant_status",
        "rollback_records",
        ["tenant_id", "rollback_status"],
        schema="automated_action",
    )


def downgrade() -> None:

    op.drop_index(
        "ix_rollback_tenant_status", table_name="rollback_records", schema="automated_action"
    )
    op.drop_index("ix_rollback_original", table_name="rollback_records", schema="automated_action")
    op.drop_index("ix_rollback_execution", table_name="rollback_records", schema="automated_action")
    op.drop_table("rollback_records", schema="automated_action")
