"""analytics_datasets was missing AnalyticsDataSet.records_ingested.

The aggregate's advance_checkpoint()/complete_rebuild() both mutate
records_ingested, but migration 0091 never gave analytics_datasets a
column for it.

Migration chain: 0152 -> 0153.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0153"
down_revision: str = "0152"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "analytics_datasets",
        sa.Column("records_ingested", sa.Integer(), nullable=False, server_default="0"),
        schema="analytics",
    )


def downgrade() -> None:
    op.drop_column("analytics_datasets", "records_ingested", schema="analytics")
