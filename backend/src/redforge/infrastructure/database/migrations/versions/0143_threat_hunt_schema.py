"""0143 — M36 migration.

Migration chain: 0142 → 0143.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0143"
down_revision: str = "0142"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.execute("CREATE SCHEMA IF NOT EXISTS threat_hunt")


def downgrade() -> None:

    op.execute("DROP SCHEMA IF EXISTS threat_hunt CASCADE")
