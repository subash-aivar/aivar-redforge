"""0097 — M33 Phase 3 ML model artifacts (BYTEA + SHA-256).

Migration chain: 0096 → 0097.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0097"
down_revision: str = "0096"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ml_model_artifacts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("model_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("artifact_bytes", postgresql.BYTEA(), nullable=False),
        sa.Column("byte_size", sa.Integer(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        schema="ml_pipeline",
    )
    op.create_index(
        "ix_ml_model_artifacts_tenant_model",
        "ml_model_artifacts",
        ["tenant_id", "model_id"],
        schema="ml_pipeline",
    )


def downgrade() -> None:
    op.drop_table("ml_model_artifacts", schema="ml_pipeline")
