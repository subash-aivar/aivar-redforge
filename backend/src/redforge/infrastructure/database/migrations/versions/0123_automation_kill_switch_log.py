"""0123 — M35 migration.

Migration chain: 0122 → 0123.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0123"
down_revision: str = "0122"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.create_table(
        "automation_kill_switch_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_type", sa.String(30), nullable=False),
        sa.Column("actor", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        schema="automated_action",
    )
    op.create_index(
        "ix_kill_switch_log_tenant_at",
        "automation_kill_switch_log",
        ["tenant_id", "recorded_at"],
        schema="automated_action",
    )


def downgrade() -> None:

    op.drop_index(
        "ix_kill_switch_log_tenant_at",
        table_name="automation_kill_switch_log",
        schema="automated_action",
    )
    op.drop_table("automation_kill_switch_log", schema="automated_action")
