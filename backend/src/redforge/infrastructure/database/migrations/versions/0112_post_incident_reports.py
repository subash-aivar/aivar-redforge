"""0112 — M34 migration.

Migration chain: 0111 → 0112.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0112"
down_revision: str = "0111"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "post_incident_reports",
        sa.Column("report_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("lessons_learned_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("format", sa.String(32), nullable=False),
        sa.Column("artifact_ref", sa.String(512), nullable=True),
        sa.Column("status", sa.String(64), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("exported_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("exported_to", sa.String(512), nullable=True),
        schema="lessons_learned",
    )

def downgrade() -> None:
    op.drop_table("post_incident_reports", schema="lessons_learned")
