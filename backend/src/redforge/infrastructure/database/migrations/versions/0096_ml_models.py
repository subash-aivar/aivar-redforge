"""0096 — M33 Phase 3 ML models.

Migration chain: 0095 → 0096.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0096"
down_revision: str = "0095"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS ml_pipeline")

    op.create_table(
        "ml_models",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("model_type", sa.String(64), nullable=False),
        sa.Column("algorithm", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("dataset_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("accuracy_metrics_json", postgresql.JSONB(), nullable=False),
        sa.Column("artifact_hash", sa.String(64), nullable=True),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("trained_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deployed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deprecated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_drift_check_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("psi_score", sa.Float(), nullable=True),
        sa.Column("governance_history_json", postgresql.JSONB(), nullable=False),
        schema="ml_pipeline",
    )
    op.create_index(
        "ix_ml_models_tenant_type_status",
        "ml_models",
        ["tenant_id", "model_type", "status"],
        schema="ml_pipeline",
    )


def downgrade() -> None:
    op.drop_table("ml_models", schema="ml_pipeline")
    op.execute("DROP SCHEMA IF EXISTS ml_pipeline CASCADE")
