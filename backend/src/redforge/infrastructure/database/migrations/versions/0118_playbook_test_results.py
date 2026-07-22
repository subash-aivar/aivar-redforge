"""0118 — M35 migration.

Migration chain: 0117 → 0118.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0118"
down_revision: str = "0117"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.create_table(
        "playbook_test_results",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("playbook_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "version_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("playbook.playbook_versions.id"),
            nullable=False,
        ),
        sa.Column("content_hash_at_test", sa.String(64), nullable=False),
        sa.Column("outcome", sa.String(20), nullable=False),
        sa.Column("steps_tested", sa.Integer(), nullable=False),
        sa.Column("steps_passed", sa.Integer(), nullable=False),
        sa.Column("coverage_paths", postgresql.JSONB(), nullable=False),
        sa.Column("executed_by", sa.Text(), nullable=False),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        schema="playbook",
    )
    op.create_index(
        "ix_playbook_test_results_pb_ver_at",
        "playbook_test_results",
        ["playbook_id", "version_id", "executed_at"],
        schema="playbook",
    )


def downgrade() -> None:

    op.drop_index(
        "ix_playbook_test_results_pb_ver_at", table_name="playbook_test_results", schema="playbook"
    )
    op.drop_table("playbook_test_results", schema="playbook")
