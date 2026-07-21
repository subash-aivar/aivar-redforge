"""0106 — M34 migration.

Migration chain: 0105 → 0106.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0106"
down_revision: str = "0105"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "regulatory_notifications",
        sa.Column("notification_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("regime", sa.String(64), nullable=False),
        sa.Column("jurisdiction", sa.String(256), nullable=False),
        sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deadline_hours", sa.Integer(), nullable=False),
        sa.Column("clock_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(64), nullable=False),
        sa.Column("draft_ref", sa.String(256), nullable=True),
        sa.Column("submission_record", postgresql.JSONB(), nullable=True),
        sa.Column("deadline_breach_records", postgresql.JSONB(), nullable=False),
        schema="regulatory_notification",
    )
    op.create_table(
        "notification_drafts",
        sa.Column("draft_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("notification_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("authored_by", sa.String(256), nullable=False),
        sa.Column("authored_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approved_by", sa.String(256), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(32), nullable=False),
        schema="regulatory_notification",
    )
    op.create_table(
        "tenant_jurisdiction_config",
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("jurisdictions", postgresql.JSONB(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        schema="regulatory_notification",
    )

def downgrade() -> None:
    op.drop_table("tenant_jurisdiction_config", schema="regulatory_notification")
    op.drop_table("notification_drafts", schema="regulatory_notification")
    op.drop_table("regulatory_notifications", schema="regulatory_notification")
