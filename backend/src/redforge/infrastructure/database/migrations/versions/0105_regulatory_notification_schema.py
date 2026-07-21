"""0105 — M34 migration.

Migration chain: 0104 → 0105.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0105"
down_revision: str = "0104"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS regulatory_notification")

def downgrade() -> None:
    op.execute("DROP SCHEMA IF EXISTS regulatory_notification CASCADE")
