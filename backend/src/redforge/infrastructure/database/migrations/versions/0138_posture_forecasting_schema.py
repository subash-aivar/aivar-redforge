"""0138 — M36 migration.

Migration chain: 0137 → 0138.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0138"
down_revision: str = "0137"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.execute("CREATE SCHEMA IF NOT EXISTS posture_forecasting")


def downgrade() -> None:

    op.execute("DROP SCHEMA IF EXISTS posture_forecasting CASCADE")
