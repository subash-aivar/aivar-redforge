"""0126 — M35 migration.

Migration chain: 0125 → 0126.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0126"
down_revision: str = "0125"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.create_table(
        "connector_health_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("connector_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("response_time_ms", sa.Integer(), nullable=True),
        sa.Column("error_detail", sa.Text(), nullable=True),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        schema="integration_hub",
    )
    op.create_index(
        "ix_connector_health_conn_at",
        "connector_health_records",
        ["connector_id", "checked_at"],
        schema="integration_hub",
    )


def downgrade() -> None:

    op.drop_index(
        "ix_connector_health_conn_at",
        table_name="connector_health_records",
        schema="integration_hub",
    )
    op.drop_table("connector_health_records", schema="integration_hub")
