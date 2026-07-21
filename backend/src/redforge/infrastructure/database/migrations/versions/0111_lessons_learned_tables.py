"""0111 — M34 migration.

Migration chain: 0110 → 0111.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0111"
down_revision: str = "0110"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS lessons_learned")
    op.create_table(
        "lessons_learned_records",
        sa.Column("ll_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(64), nullable=False),
        sa.Column("reviewed_by", sa.String(256), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finalized_by", sa.String(256), nullable=True),
        sa.Column("finalized_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("campaign_retargeting_suggestion_ref", sa.String(256), nullable=True),
        sa.Column("confirmed_technique_ids", postgresql.JSONB(), nullable=False),
        schema="lessons_learned",
    )
    op.create_table(
        "lesson_items",
        sa.Column("item_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("ll_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("impact_summary", sa.Text(), nullable=False),
        schema="lessons_learned",
    )
    op.create_table(
        "action_items",
        sa.Column("action_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("ll_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("owner", sa.String(256), nullable=False),
        sa.Column("priority", sa.String(64), nullable=False),
        sa.Column("due_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(64), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        schema="lessons_learned",
    )

def downgrade() -> None:
    op.drop_table("action_items", schema="lessons_learned")
    op.drop_table("lesson_items", schema="lessons_learned")
    op.drop_table("lessons_learned_records", schema="lessons_learned")
    op.execute("DROP SCHEMA IF EXISTS lessons_learned CASCADE")
