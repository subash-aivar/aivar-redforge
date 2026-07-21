"""0099 — M33 Phase 4 report delivery audit log.

Migration chain: 0098 → 0099.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0099"
down_revision: str = "0098"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "report_delivery_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("instance_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("channel", sa.String(32), nullable=False),
        sa.Column("recipients_json", postgresql.JSONB(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("artifact_ref", sa.String(512), nullable=False),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=False),
        schema="reporting",
    )
    op.create_index(
        "ix_report_delivery_log_tenant_at",
        "report_delivery_log",
        ["tenant_id", "delivered_at"],
        schema="reporting",
    )


def downgrade() -> None:
    op.drop_table("report_delivery_log", schema="reporting")
