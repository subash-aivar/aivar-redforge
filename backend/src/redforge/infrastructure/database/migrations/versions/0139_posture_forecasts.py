"""0139 — M36 migration.

Migration chain: 0138 → 0139.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0139"
down_revision: str = "0138"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.create_table(
        "posture_forecasts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("predicted_30d", sa.Float(), nullable=False),
        sa.Column("predicted_60d", sa.Float(), nullable=False),
        sa.Column("predicted_90d", sa.Float(), nullable=False),
        sa.Column("model_id", sa.String(128), nullable=False),
        sa.Column("model_version", sa.Integer(), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        schema="posture_forecasting",
    )
    op.create_index(
        "ix_forecasts_tenant_generated",
        "posture_forecasts",
        ["tenant_id", "generated_at"],
        schema="posture_forecasting",
    )


def downgrade() -> None:

    op.drop_index(
        "ix_forecasts_tenant_generated",
        table_name="posture_forecasts",
        schema="posture_forecasting",
    )
    op.drop_table("posture_forecasts", schema="posture_forecasting")
