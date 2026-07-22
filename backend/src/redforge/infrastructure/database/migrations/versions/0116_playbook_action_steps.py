"""0116 — M35 migration.

Migration chain: 0115 → 0116.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0116"
down_revision: str = "0115"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.create_table(
        "playbook_action_steps",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "version_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("playbook.playbook_versions.id"),
            nullable=False,
        ),
        sa.Column("step_number", sa.Integer(), nullable=False),
        sa.Column("action_type", sa.Text(), nullable=False),
        sa.Column("connector_type", sa.String(50), nullable=False),
        sa.Column("target_selector_expr", sa.Text(), nullable=False),
        sa.Column("parameters", postgresql.JSONB(), nullable=False),
        sa.Column("impact_level", sa.String(20), nullable=False),
        sa.Column("rollback_definition", postgresql.JSONB(), nullable=True),
        sa.Column("max_execution_seconds", sa.Integer(), nullable=False, server_default="120"),
        schema="playbook",
    )
    op.create_index(
        "ix_playbook_action_steps_version_step",
        "playbook_action_steps",
        ["version_id", "step_number"],
        schema="playbook",
    )


def downgrade() -> None:

    op.drop_index(
        "ix_playbook_action_steps_version_step",
        table_name="playbook_action_steps",
        schema="playbook",
    )
    op.drop_table("playbook_action_steps", schema="playbook")
