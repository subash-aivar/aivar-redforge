"""Dead Letter Queue persistent store — Sprint 28.

Creates the dead_letter_entries table for durable DLQ storage.
Replaces the in-memory InMemoryDeadLetterQueue for production deployments.

Revision ID: 0008
Revises: 0007
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0008"
down_revision: str = "0007"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "dead_letter_entries",
        sa.Column("entry_id", sa.Text, primary_key=True),
        sa.Column("source_projection", sa.Text, nullable=False),
        sa.Column("event_id", sa.Text, nullable=False),
        sa.Column("event_type", sa.Text, nullable=False),
        sa.Column("payload", JSONB, nullable=False),
        sa.Column("error_message", sa.Text, nullable=False),
        sa.Column("retry_count", sa.Integer, nullable=False, server_default="0"),
        # status: pending | requeued | replayed
        sa.Column("status", sa.Text, nullable=False, server_default="pending"),
        sa.Column("first_failed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_failed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("organization_id", sa.Text, nullable=False),
        sa.Column("version", sa.Integer, nullable=False, server_default="0"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
    )

    # Fast org+status queries — main operational access pattern
    op.create_index(
        "ix_dle_org_status",
        "dead_letter_entries",
        ["organization_id", "status"],
    )

    # Filter by projection within an org
    op.create_index(
        "ix_dle_org_projection",
        "dead_letter_entries",
        ["organization_id", "source_projection"],
    )

    # Event deduplication checks
    op.create_index(
        "ix_dle_event_id",
        "dead_letter_entries",
        ["event_id"],
    )

    # Partial index for replay worker — only requeued entries
    op.execute(
        "CREATE INDEX ix_dle_requeued ON dead_letter_entries (last_failed_at ASC) "
        "WHERE status = 'requeued'"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_dle_requeued")
    op.drop_index("ix_dle_event_id", table_name="dead_letter_entries")
    op.drop_index("ix_dle_org_projection", table_name="dead_letter_entries")
    op.drop_index("ix_dle_org_status", table_name="dead_letter_entries")
    op.drop_table("dead_letter_entries")
