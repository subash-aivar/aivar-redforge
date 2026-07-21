"""0092 — M33 Phase 1 ATT&CK technique reference table.

Migration chain: 0091 → 0092.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0092"
down_revision: str = "0091"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "attck_techniques",
        sa.Column("technique_id", sa.String(32), primary_key=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("tactic", sa.String(128), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        schema="analytics",
    )


def downgrade() -> None:
    op.drop_table("attck_techniques", schema="analytics")
