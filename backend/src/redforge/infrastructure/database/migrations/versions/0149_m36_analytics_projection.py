"""0149 — M36 migration.

Migration chain: 0148 → 0149.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0149"
down_revision: str = "0148"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.execute("CREATE SCHEMA IF NOT EXISTS analytics")
    op.create_table(
        "m36_suggestion_metrics",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("suggestion_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("event_type", sa.String(80), nullable=False),
        sa.Column("target_type", sa.String(80), nullable=True),
        sa.Column("confidence_score", sa.Float(), nullable=True),
        sa.Column("event_ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        schema="analytics",
    )
    op.create_index(
        "ix_m36_metrics_tenant_ts",
        "m36_suggestion_metrics",
        ["tenant_id", "event_ts"],
        schema="analytics",
    )
    op.create_index(
        "ix_m36_metrics_tenant_type",
        "m36_suggestion_metrics",
        ["tenant_id", "target_type", "event_ts"],
        schema="analytics",
    )


def downgrade() -> None:

    op.drop_index(
        "ix_m36_metrics_tenant_type", table_name="m36_suggestion_metrics", schema="analytics"
    )
    op.drop_index(
        "ix_m36_metrics_tenant_ts", table_name="m36_suggestion_metrics", schema="analytics"
    )
    op.drop_table("m36_suggestion_metrics", schema="analytics")
