"""0043 — M24 Phase 3 Evidence Recommendation & Auto-Linking Engine."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0043"
down_revision: str = "0042"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "recommendation_batches",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("period_id", sa.String(26), nullable=False),
        sa.Column("assessment_id", sa.String(26), nullable=True),
        sa.Column("generation_fingerprint", sa.String(128), nullable=False),
        sa.Column(
            "recommendation_ids",
            postgresql.ARRAY(sa.String()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column("created_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("updated_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "skipped_duplicate_count", sa.Integer(), nullable=False, server_default="0"
        ),
        sa.Column("generated_by", sa.String(26), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "organization_id",
            "generation_fingerprint",
            name="uq_recommendation_batches_org_fingerprint",
        ),
    )
    op.create_index(
        "ix_recommendation_batches_org_period",
        "recommendation_batches",
        ["organization_id", "period_id"],
    )
    op.create_index(
        "ix_recommendation_batches_org_created",
        "recommendation_batches",
        ["organization_id", "created_at"],
    )

    op.create_table(
        "evidence_recommendations",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("batch_id", sa.String(26), nullable=False),
        sa.Column("assessment_id", sa.String(26), nullable=False),
        sa.Column("period_id", sa.String(26), nullable=False),
        sa.Column("requirement_id", sa.String(26), nullable=False),
        sa.Column("framework_key", sa.String(80), nullable=False),
        sa.Column("source_kind", sa.String(40), nullable=False),
        sa.Column("source_entity_id", sa.String(64), nullable=False),
        sa.Column(
            "candidates",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("confidence", sa.String(32), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False, server_default=""),
        sa.Column("status", sa.String(20), nullable=False, server_default="recommended"),
        sa.Column("dedup_key", sa.String(200), nullable=False),
        sa.Column("decision", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("linked_evidence_id", sa.String(26), nullable=True),
        sa.Column("created_by", sa.String(26), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_evidence_recommendations_org_period",
        "evidence_recommendations",
        ["organization_id", "period_id"],
    )
    op.create_index(
        "ix_evidence_recommendations_org_assessment",
        "evidence_recommendations",
        ["organization_id", "assessment_id"],
    )
    op.create_index(
        "ix_evidence_recommendations_org_status",
        "evidence_recommendations",
        ["organization_id", "status"],
    )
    op.create_index(
        "ix_evidence_recommendations_org_updated",
        "evidence_recommendations",
        ["organization_id", "updated_at"],
    )
    op.create_index(
        "uq_evidence_recommendations_org_dedup_active",
        "evidence_recommendations",
        ["organization_id", "dedup_key"],
        unique=True,
        postgresql_where=sa.text(
            "status IN ('recommended', 'accepted', 'linked')"
        ),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_evidence_recommendations_org_dedup_active",
        table_name="evidence_recommendations",
    )
    op.drop_index(
        "ix_evidence_recommendations_org_updated",
        table_name="evidence_recommendations",
    )
    op.drop_index(
        "ix_evidence_recommendations_org_status",
        table_name="evidence_recommendations",
    )
    op.drop_index(
        "ix_evidence_recommendations_org_assessment",
        table_name="evidence_recommendations",
    )
    op.drop_index(
        "ix_evidence_recommendations_org_period",
        table_name="evidence_recommendations",
    )
    op.drop_table("evidence_recommendations")
    op.drop_index(
        "ix_recommendation_batches_org_created", table_name="recommendation_batches"
    )
    op.drop_index(
        "ix_recommendation_batches_org_period", table_name="recommendation_batches"
    )
    op.drop_table("recommendation_batches")
