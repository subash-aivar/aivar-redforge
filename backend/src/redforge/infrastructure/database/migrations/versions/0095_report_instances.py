"""0095 — M33 Phase 2 report instances.

Migration chain: 0094 → 0095.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0095"
down_revision: str = "0094"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "report_instances",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("template_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scheduled_report_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("report_type", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("artifact_json", postgresql.JSONB(), nullable=False),
        sa.Column("narrative", sa.Text(), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("generated_by", sa.String(256), nullable=False),
        schema="reporting",
    )
    op.create_index(
        "ix_report_instances_tenant_generated",
        "report_instances",
        ["tenant_id", "generated_at"],
        schema="reporting",
    )


def downgrade() -> None:
    op.drop_table("report_instances", schema="reporting")
