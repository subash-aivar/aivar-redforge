"""0135 — M36 migration.

Migration chain: 0134 → 0135.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0135"
down_revision: str = "0134"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.create_table(
        "autonomous_operations_policies",
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("kill_switch_active", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("review_required", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("min_confidence_by_type", postgresql.JSONB(), nullable=False),
        sa.Column("enabled_target_types", postgresql.JSONB(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        schema="autonomous_intelligence",
    )


def downgrade() -> None:

    op.drop_table("autonomous_operations_policies", schema="autonomous_intelligence")
