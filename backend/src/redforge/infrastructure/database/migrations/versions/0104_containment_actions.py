"""0104 — M34 migration.

Migration chain: 0103 → 0104.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0104"
down_revision: str = "0103"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "containment_actions",
        sa.Column("action_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("action_type", sa.String(64), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("authorization_level_required", sa.String(32), nullable=False),
        sa.Column("authorized_by", sa.String(256), nullable=True),
        sa.Column("authorized_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("executed_by", sa.String(256), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("evidence_ref", sa.String(512), nullable=True),
        sa.Column("status", sa.String(64), nullable=False),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        sa.Column("rollback_ref", sa.String(512), nullable=True),
        schema="incident",
    )
    op.create_index("ix_containment_tenant_incident", "containment_actions", ["tenant_id", "incident_id"], schema="incident")

def downgrade() -> None:
    op.drop_table("containment_actions", schema="incident")
