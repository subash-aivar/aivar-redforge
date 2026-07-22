"""0146 — M36 migration.

Migration chain: 0145 → 0146.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0146"
down_revision: str = "0145"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.create_table(
        "threat_hunt_configurations",
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("min_signal_strength", sa.Float(), nullable=False, server_default="0.5"),
        sa.Column("enabled_signal_types", postgresql.JSONB(), nullable=False),
        schema="threat_hunt",
    )


def downgrade() -> None:

    op.drop_table("threat_hunt_configurations", schema="threat_hunt")
