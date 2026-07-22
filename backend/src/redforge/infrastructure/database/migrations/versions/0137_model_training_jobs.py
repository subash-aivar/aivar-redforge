"""0137 — M36 migration.

Migration chain: 0136 → 0137.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0137"
down_revision: str = "0136"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.create_table(
        "model_training_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("model_id", sa.String(128), nullable=False),
        sa.Column("target_type", sa.String(80), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_detail", sa.Text(), nullable=True),
        schema="autonomous_intelligence",
    )
    op.create_index(
        "ix_training_jobs_tenant_status",
        "model_training_jobs",
        ["tenant_id", "status"],
        schema="autonomous_intelligence",
    )


def downgrade() -> None:

    op.drop_index(
        "ix_training_jobs_tenant_status",
        table_name="model_training_jobs",
        schema="autonomous_intelligence",
    )
    op.drop_table("model_training_jobs", schema="autonomous_intelligence")
