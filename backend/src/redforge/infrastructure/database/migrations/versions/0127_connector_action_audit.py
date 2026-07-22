"""0127 — M35 migration.

Migration chain: 0126 → 0127.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0127"
down_revision: str = "0126"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.create_table(
        "connector_action_audit",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("connector_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("execution_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("record_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("action_type", sa.Text(), nullable=False),
        sa.Column("outcome", sa.String(20), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=False),
        schema="integration_hub",
    )
    op.create_index(
        "ix_caa_connector_at",
        "connector_action_audit",
        ["connector_id", "executed_at"],
        schema="integration_hub",
    )
    op.create_index(
        "ix_caa_tenant_at",
        "connector_action_audit",
        ["tenant_id", "executed_at"],
        schema="integration_hub",
    )


def downgrade() -> None:

    op.drop_index("ix_caa_tenant_at", table_name="connector_action_audit", schema="integration_hub")
    op.drop_index(
        "ix_caa_connector_at", table_name="connector_action_audit", schema="integration_hub"
    )
    op.drop_table("connector_action_audit", schema="integration_hub")
