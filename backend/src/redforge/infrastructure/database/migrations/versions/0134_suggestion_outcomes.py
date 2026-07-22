"""0134 — M36 migration.

Migration chain: 0133 → 0134.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0134"
down_revision: str = "0133"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.create_table(
        "suggestion_outcomes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("suggestion_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_type", sa.String(80), nullable=False),
        sa.Column("outcome_type", sa.String(40), nullable=False),
        sa.Column("measurement_window_days", sa.Integer(), nullable=False),
        sa.Column("baseline_metric", sa.Float(), nullable=False),
        sa.Column("observed_metric", sa.Float(), nullable=True),
        sa.Column("delta", sa.Float(), nullable=True),
        sa.Column("measured_at", sa.DateTime(timezone=True), nullable=True),
        schema="autonomous_intelligence",
    )
    op.create_index(
        "ix_outcomes_suggestion",
        "suggestion_outcomes",
        ["suggestion_id"],
        schema="autonomous_intelligence",
    )
    op.create_index(
        "ix_outcomes_tenant_type",
        "suggestion_outcomes",
        ["tenant_id", "target_type"],
        schema="autonomous_intelligence",
    )


def downgrade() -> None:

    op.drop_index(
        "ix_outcomes_tenant_type",
        table_name="suggestion_outcomes",
        schema="autonomous_intelligence",
    )
    op.drop_index(
        "ix_outcomes_suggestion", table_name="suggestion_outcomes", schema="autonomous_intelligence"
    )
    op.drop_table("suggestion_outcomes", schema="autonomous_intelligence")
