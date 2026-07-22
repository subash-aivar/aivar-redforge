"""0140 — M36 migration.

Migration chain: 0139 → 0140.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0140"
down_revision: str = "0139"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.create_table(
        "forecast_accuracy_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("forecast_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("horizon_days", sa.Integer(), nullable=False),
        sa.Column("actual_score", sa.Float(), nullable=False),
        sa.Column("predicted_score", sa.Float(), nullable=False),
        sa.Column("absolute_error", sa.Float(), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        schema="posture_forecasting",
    )
    op.create_index(
        "ix_forecast_acc_forecast",
        "forecast_accuracy_records",
        ["forecast_id", "horizon_days"],
        schema="posture_forecasting",
    )


def downgrade() -> None:

    op.drop_index(
        "ix_forecast_acc_forecast",
        table_name="forecast_accuracy_records",
        schema="posture_forecasting",
    )
    op.drop_table("forecast_accuracy_records", schema="posture_forecasting")
