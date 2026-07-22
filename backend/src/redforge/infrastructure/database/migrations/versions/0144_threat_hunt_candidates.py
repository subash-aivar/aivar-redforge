"""0144 — M36 migration.

Migration chain: 0143 → 0144.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0144"
down_revision: str = "0143"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.create_table(
        "threat_hunt_candidates",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("detection_logic_draft", sa.Text(), nullable=False),
        sa.Column("detection_rule_format", sa.String(20), nullable=False),
        sa.Column("confidence_score", sa.Float(), nullable=False),
        sa.Column("candidate_status", sa.String(30), nullable=False),
        sa.Column("promoted_rule_version_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("review_notes", sa.Text(), nullable=True),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reviewed_by", sa.Text(), nullable=True),
        schema="threat_hunt",
    )
    op.create_index(
        "ix_hunt_candidates_tenant_status",
        "threat_hunt_candidates",
        ["tenant_id", "candidate_status"],
        schema="threat_hunt",
    )


def downgrade() -> None:

    op.drop_index(
        "ix_hunt_candidates_tenant_status",
        table_name="threat_hunt_candidates",
        schema="threat_hunt",
    )
    op.drop_table("threat_hunt_candidates", schema="threat_hunt")
