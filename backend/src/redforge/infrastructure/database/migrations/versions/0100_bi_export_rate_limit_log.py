"""0100 — M33 Phase 4 BI export rate limit audit log.

Migration chain: 0099 → 0100.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0100"
down_revision: str = "0099"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "bi_export_rate_limit_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("actor", sa.String(256), nullable=False),
        sa.Column("export_format", sa.String(32), nullable=False),
        sa.Column("dataset_or_instance_ref", sa.String(256), nullable=False),
        sa.Column("allowed", sa.Boolean(), nullable=False),
        sa.Column("window_key", sa.String(64), nullable=False),
        sa.Column("request_count_in_window", sa.Integer(), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        schema="reporting",
    )
    op.create_index(
        "ix_bi_export_rate_limit_tenant_window",
        "bi_export_rate_limit_log",
        ["tenant_id", "window_key"],
        schema="reporting",
    )


def downgrade() -> None:
    op.drop_table("bi_export_rate_limit_log", schema="reporting")
