"""0133 — M36 migration.

Migration chain: 0132 → 0133.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0133"
down_revision: str = "0132"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.create_table(
        "intelligence_suggestions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_type", sa.String(80), nullable=False),
        sa.Column("target_context", sa.String(80), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("status", sa.String(40), nullable=False),
        sa.Column("confidence_score", sa.Float(), nullable=False),
        sa.Column("model_id", sa.String(128), nullable=False),
        sa.Column("model_version", sa.Integer(), nullable=False),
        sa.Column("rationale_summary", sa.Text(), nullable=False),
        sa.Column("supporting_signal_refs", postgresql.JSONB(), nullable=False),
        sa.Column("proposed_change_payload", postgresql.JSONB(), nullable=False),
        sa.Column("priority", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("review_deadline_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("approved_by", sa.Text(), nullable=True),
        sa.Column("rejected_by", sa.Text(), nullable=True),
        sa.Column("rejection_reason", sa.Text(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        schema="autonomous_intelligence",
    )
    op.create_index(
        "ix_suggestions_tenant_status",
        "intelligence_suggestions",
        ["tenant_id", "status"],
        schema="autonomous_intelligence",
    )
    op.create_index(
        "ix_suggestions_tenant_type_conf",
        "intelligence_suggestions",
        ["tenant_id", "target_type", "confidence_score"],
        schema="autonomous_intelligence",
    )
    op.create_index(
        "ix_suggestions_deadline",
        "intelligence_suggestions",
        ["status", "review_deadline_at"],
        schema="autonomous_intelligence",
    )


def downgrade() -> None:

    op.drop_index(
        "ix_suggestions_deadline",
        table_name="intelligence_suggestions",
        schema="autonomous_intelligence",
    )
    op.drop_index(
        "ix_suggestions_tenant_type_conf",
        table_name="intelligence_suggestions",
        schema="autonomous_intelligence",
    )
    op.drop_index(
        "ix_suggestions_tenant_status",
        table_name="intelligence_suggestions",
        schema="autonomous_intelligence",
    )
    op.drop_table("intelligence_suggestions", schema="autonomous_intelligence")
