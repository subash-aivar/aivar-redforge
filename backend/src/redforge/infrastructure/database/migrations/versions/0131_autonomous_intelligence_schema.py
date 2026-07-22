"""0131 — M36 migration.

Migration chain: 0130 → 0131.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0131"
down_revision: str = "0130"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.execute("CREATE SCHEMA IF NOT EXISTS autonomous_intelligence")


def downgrade() -> None:

    op.execute("DROP SCHEMA IF EXISTS autonomous_intelligence CASCADE")
