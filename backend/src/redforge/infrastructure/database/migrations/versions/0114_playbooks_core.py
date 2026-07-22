"""0114 — M35 migration.

Migration chain: 0113 → 0114.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0114"
down_revision: str = "0113"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.execute("CREATE SCHEMA IF NOT EXISTS playbook")
    op.create_table(
        "playbooks",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("current_version_number", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_impact_level", sa.String(20), nullable=False),
        sa.Column("created_by", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        schema="playbook",
    )
    op.create_index(
        "ix_playbooks_tenant_status", "playbooks", ["tenant_id", "status"], schema="playbook"
    )
    op.create_index(
        "ix_playbooks_tenant_name", "playbooks", ["tenant_id", "name"], schema="playbook"
    )


def downgrade() -> None:

    op.drop_index("ix_playbooks_tenant_name", table_name="playbooks", schema="playbook")
    op.drop_index("ix_playbooks_tenant_status", table_name="playbooks", schema="playbook")
    op.drop_table("playbooks", schema="playbook")
    op.execute("DROP SCHEMA IF EXISTS playbook CASCADE")
