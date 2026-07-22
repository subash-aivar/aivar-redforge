"""0117 — M35 migration.

Migration chain: 0116 → 0117.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0117"
down_revision: str = "0116"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.create_table(
        "playbook_trigger_configs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "playbook_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("playbook.playbooks.id"),
            nullable=False,
        ),
        sa.Column("source_context", sa.String(40), nullable=False),
        sa.Column("trigger_type", sa.Text(), nullable=False),
        sa.Column("severity_threshold", sa.String(40), nullable=True),
        sa.Column("asset_tag_filter", postgresql.JSONB(), nullable=True),
        sa.Column("rate_limit_window_seconds", sa.Integer(), nullable=False, server_default="300"),
        sa.Column("rate_limit_max_invocations", sa.Integer(), nullable=False, server_default="1"),
        schema="playbook",
    )
    op.create_index(
        "ix_playbook_triggers_tenant_source_type",
        "playbook_trigger_configs",
        ["tenant_id", "source_context", "trigger_type"],
        schema="playbook",
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_playbook_triggers_asset_tags "
        "ON playbook.playbook_trigger_configs USING GIN (asset_tag_filter)"
    )


def downgrade() -> None:

    op.execute("DROP INDEX IF EXISTS playbook.ix_playbook_triggers_asset_tags")
    op.drop_index(
        "ix_playbook_triggers_tenant_source_type",
        table_name="playbook_trigger_configs",
        schema="playbook",
    )
    op.drop_table("playbook_trigger_configs", schema="playbook")
