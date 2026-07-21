"""0107 — M34 migration.

Migration chain: 0106 → 0107.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0107"
down_revision: str = "0106"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "notification_deadlines",
        sa.Column("deadline_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("notification_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("regime", sa.String(64), nullable=False),
        sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deadline_hours", sa.Integer(), nullable=False),
        sa.Column("clock_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("cancelled", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("breached_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("alerts_sent", postgresql.JSONB(), nullable=False),
        schema="regulatory_notification",
    )
    op.create_index("ix_notification_deadlines_deadline_at", "notification_deadlines", ["deadline_at"], schema="regulatory_notification")

def downgrade() -> None:
    op.drop_table("notification_deadlines", schema="regulatory_notification")
