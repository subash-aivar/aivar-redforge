
"""0077 — M31 Phase 2 threat profiles and risk score snapshots.

Creates:
- ai_threat_profiles
- ai_risk_score_snapshots

Migration chain: 0076 → 0077.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0077"
down_revision: str = "0076"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ai_threat_profiles",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column(
            "ai_system_asset_id", postgresql.UUID(as_uuid=True), nullable=False, index=True
        ),
        sa.Column("ai_system_kind", sa.String(64), nullable=False),
        sa.Column("prompt_injection_json", postgresql.JSONB(), nullable=True),
        sa.Column("model_extraction_json", postgresql.JSONB(), nullable=True),
        sa.Column("training_data_leakage_json", postgresql.JSONB(), nullable=True),
        sa.Column(
            "category_assessments_json",
            postgresql.JSONB(),
            nullable=False,
            server_default="[]",
        ),
        sa.Column(
            "evidence_refs_json", postgresql.JSONB(), nullable=False, server_default="[]"
        ),
        sa.Column("last_assessed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "requires_reassessment",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "archived", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "tenant_id",
            "ai_system_asset_id",
            name="uq_ai_threat_profiles_tenant_asset",
        ),
        schema="ai_posture",
    )

    op.create_table(
        "ai_risk_score_snapshots",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("ai_system_asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("composite_score", sa.Float(), nullable=False),
        sa.Column("score_components_json", postgresql.JSONB(), nullable=False),
        sa.Column("computed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("staleness_bound_hours", sa.Integer(), nullable=False, server_default="24"),
        sa.Column("score_input_version", sa.String(64), nullable=False),
        schema="ai_posture",
    )
    op.create_index(
        "ix_ai_risk_score_snapshots_tenant_asset_computed",
        "ai_risk_score_snapshots",
        ["tenant_id", "ai_system_asset_id", "computed_at"],
        unique=False,
        schema="ai_posture",
    )


def downgrade() -> None:
    op.drop_index(
        "ix_ai_risk_score_snapshots_tenant_asset_computed",
        table_name="ai_risk_score_snapshots",
        schema="ai_posture",
    )
    op.drop_table("ai_risk_score_snapshots", schema="ai_posture")
    op.drop_table("ai_threat_profiles", schema="ai_posture")
