"""0132 — M36 migration.

Migration chain: 0131 → 0132.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0132"
down_revision: str = "0131"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.create_table(
        "optimization_models",
        sa.Column("id", sa.String(128), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_type", sa.String(80), nullable=False),
        sa.Column("model_version", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("accuracy_metrics", postgresql.JSONB(), nullable=False),
        sa.Column("conformity_assessment_ref", sa.Text(), nullable=True),
        sa.Column("feedback_sample_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("retraining_threshold", sa.Integer(), nullable=False, server_default="50"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deployed_at", sa.DateTime(timezone=True), nullable=True),
        schema="autonomous_intelligence",
    )
    op.create_index(
        "ix_opt_models_tenant_type_status",
        "optimization_models",
        ["tenant_id", "target_type", "status"],
        schema="autonomous_intelligence",
    )


def downgrade() -> None:

    op.drop_index(
        "ix_opt_models_tenant_type_status",
        table_name="optimization_models",
        schema="autonomous_intelligence",
    )
    op.drop_table("optimization_models", schema="autonomous_intelligence")
