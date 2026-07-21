"""0098 — M33 Phase 3 predictive risk signals.

Migration chain: 0097 → 0098.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0098"
down_revision: str = "0097"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "predictive_risk_signals",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("model_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_ref_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("signal_type", sa.String(64), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("features_json", postgresql.JSONB(), nullable=False),
        schema="ml_pipeline",
    )
    op.create_index(
        "ix_predictive_risk_signals_tenant_asset",
        "predictive_risk_signals",
        ["tenant_id", "asset_ref_id"],
        schema="ml_pipeline",
    )
    op.create_index(
        "ix_predictive_risk_signals_expires",
        "predictive_risk_signals",
        ["tenant_id", "expires_at"],
        schema="ml_pipeline",
    )


def downgrade() -> None:
    op.drop_table("predictive_risk_signals", schema="ml_pipeline")
