"""0128 — M35 migration.

Migration chain: 0127 → 0128.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0128"
down_revision: str = "0127"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.create_table(
        "connector_rate_limit_tracking",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("connector_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("action_count", sa.Integer(), nullable=False),
        sa.Column("budget_consumed_percent", sa.Float(), nullable=False),
        schema="integration_hub",
    )
    op.create_index(
        "ix_rate_limit_conn_start",
        "connector_rate_limit_tracking",
        ["connector_id", "window_start"],
        schema="integration_hub",
    )


def downgrade() -> None:

    op.drop_index(
        "ix_rate_limit_conn_start",
        table_name="connector_rate_limit_tracking",
        schema="integration_hub",
    )
    op.drop_table("connector_rate_limit_tracking", schema="integration_hub")
