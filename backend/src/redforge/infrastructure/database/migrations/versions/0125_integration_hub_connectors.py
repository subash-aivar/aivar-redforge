"""0125 — M35 migration.

Migration chain: 0124 → 0125.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0125"
down_revision: str = "0124"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.execute("CREATE SCHEMA IF NOT EXISTS integration_hub")
    op.create_table(
        "connector_registrations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("connector_type", sa.String(50), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="REGISTERED"),
        sa.Column("credential_vault_key", sa.Text(), nullable=False),
        sa.Column("credential_type", sa.String(30), nullable=False),
        sa.Column("base_url", sa.Text(), nullable=True),
        sa.Column("configuration", postgresql.JSONB(), nullable=True),
        sa.Column("circuit_state", sa.String(20), nullable=False, server_default="CLOSED"),
        sa.Column("circuit_failure_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("circuit_opened_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_health_check_at", sa.DateTime(timezone=True), nullable=True),
        schema="integration_hub",
    )
    op.create_index(
        "ix_connectors_tenant_type",
        "connector_registrations",
        ["tenant_id", "connector_type"],
        schema="integration_hub",
    )
    op.create_index(
        "ix_connectors_tenant_status",
        "connector_registrations",
        ["tenant_id", "status"],
        schema="integration_hub",
    )


def downgrade() -> None:

    op.drop_index(
        "ix_connectors_tenant_status",
        table_name="connector_registrations",
        schema="integration_hub",
    )
    op.drop_index(
        "ix_connectors_tenant_type", table_name="connector_registrations", schema="integration_hub"
    )
    op.drop_table("connector_registrations", schema="integration_hub")
    op.execute("DROP SCHEMA IF EXISTS integration_hub CASCADE")
