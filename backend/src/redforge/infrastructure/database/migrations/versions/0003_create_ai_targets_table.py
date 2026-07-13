"""Create ai_targets table.

Revision ID: 0003
Revises: 0002
Create Date: 2025-01-20 00:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ai_targets",
        sa.Column("id", sa.String(26), nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("name", sa.String(150), nullable=False),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column("target_type", sa.String(30), nullable=False),
        sa.Column("provider", sa.String(30), nullable=False),
        sa.Column("endpoint", sa.String(2048), nullable=False),
        sa.Column("auth_reference", sa.String(500), nullable=True),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("tags_json", sa.Text, nullable=False, server_default="[]"),
        sa.Column("policies_json", sa.Text, nullable=False, server_default="[]"),
        sa.Column("metadata_json", sa.Text, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_ai_targets"),
    )
    op.create_index("ix_ai_targets_organization_id", "ai_targets", ["organization_id"])


def downgrade() -> None:
    op.drop_index("ix_ai_targets_organization_id", table_name="ai_targets")
    op.drop_table("ai_targets")
