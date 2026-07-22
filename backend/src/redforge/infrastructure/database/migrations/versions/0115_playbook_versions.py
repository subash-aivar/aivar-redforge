"""0115 — M35 migration.

Migration chain: 0114 → 0115.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0115"
down_revision: str = "0114"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.create_table(
        "playbook_versions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "playbook_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("playbook.playbooks.id"),
            nullable=False,
        ),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False, server_default=""),
        sa.Column("published_by", sa.Text(), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("playbook_id", "version_number", name="uq_playbook_version"),
        schema="playbook",
    )
    op.create_index(
        "ix_playbook_versions_tenant_status",
        "playbook_versions",
        ["tenant_id", "status"],
        schema="playbook",
    )


def downgrade() -> None:

    op.drop_index(
        "ix_playbook_versions_tenant_status", table_name="playbook_versions", schema="playbook"
    )
    op.drop_table("playbook_versions", schema="playbook")
