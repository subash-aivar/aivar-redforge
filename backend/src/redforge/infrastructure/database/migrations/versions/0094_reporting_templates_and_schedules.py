"""0094 — M33 Phase 2 reporting templates and schedules.

Migration chain: 0093 → 0094.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0094"
down_revision: str = "0093"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS reporting")

    op.create_table(
        "report_templates",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("report_type", sa.String(64), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("sections_json", postgresql.JSONB(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("is_platform", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        schema="reporting",
    )
    op.create_index(
        "ix_report_templates_type",
        "report_templates",
        ["report_type"],
        schema="reporting",
    )

    op.create_table(
        "scheduled_reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("template_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("schedule_cron", sa.String(64), nullable=False),
        sa.Column("parameters_json", postgresql.JSONB(), nullable=False),
        sa.Column("recipients_json", postgresql.JSONB(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_invocation_key", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        schema="reporting",
    )
    op.create_index(
        "ix_scheduled_reports_tenant_next",
        "scheduled_reports",
        ["tenant_id", "next_run_at"],
        schema="reporting",
    )


def downgrade() -> None:
    op.drop_table("scheduled_reports", schema="reporting")
    op.drop_table("report_templates", schema="reporting")
    op.execute("DROP SCHEMA IF EXISTS reporting CASCADE")
