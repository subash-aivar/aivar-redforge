"""0141 — M36 migration.

Migration chain: 0140 → 0141.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0141"
down_revision: str = "0140"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.create_table(
        "forecast_configurations",
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("forecast_frequency_hours", sa.Integer(), nullable=False, server_default="24"),
        sa.Column("signal_weights", postgresql.JSONB(), nullable=False),
        schema="posture_forecasting",
    )


def downgrade() -> None:

    op.drop_table("forecast_configurations", schema="posture_forecasting")
