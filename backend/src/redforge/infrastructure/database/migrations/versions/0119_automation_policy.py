"""0119 — M35 migration.

Migration chain: 0118 → 0119.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0119"
down_revision: str = "0118"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.create_table(
        "automation_policy",
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("kill_switch_state", sa.String(20), nullable=False, server_default="ARMED"),
        sa.Column("kill_switch_triggered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("kill_switch_triggered_by", sa.Text(), nullable=True),
        sa.Column("max_concurrent_executions", sa.Integer(), nullable=False, server_default="5"),
        sa.Column("max_actions_per_hour", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("allowed_connector_types", postgresql.JSONB(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        schema="playbook",
    )


def downgrade() -> None:

    op.drop_table("automation_policy", schema="playbook")
