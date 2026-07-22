"""0142 — M36 migration.

Migration chain: 0141 → 0142.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0142"
down_revision: str = "0141"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.create_table(
        "forecast_input_snapshots",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("forecast_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("baseline_exposure_score", sa.Float(), nullable=False),
        sa.Column("remediation_velocity_per_day", sa.Float(), nullable=False),
        sa.Column("open_critical_count", sa.Integer(), nullable=False),
        sa.Column("open_high_count", sa.Integer(), nullable=False),
        sa.Column("snapshot_at", sa.DateTime(timezone=True), nullable=False),
        schema="posture_forecasting",
    )
    op.create_index(
        "ix_forecast_snap_forecast",
        "forecast_input_snapshots",
        ["forecast_id"],
        schema="posture_forecasting",
    )


def downgrade() -> None:

    op.drop_index(
        "ix_forecast_snap_forecast",
        table_name="forecast_input_snapshots",
        schema="posture_forecasting",
    )
    op.drop_table("forecast_input_snapshots", schema="posture_forecasting")
