"""0083 — M32 Phase 4 ExposureReductionPlan persistence.

Maps frozen plan migration 0047 onto the live Alembic chain after 0082:
- remediation_impact schema
- exposure_reduction_plans table

Migration chain: 0082 → 0083.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0083"
down_revision: str = "0082"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS remediation_impact")

    op.create_table(
        "exposure_reduction_plans",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("committed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("committed_by", sa.String(256), nullable=True),
        sa.Column("projected_exposure_reduction", sa.Float(), nullable=False),
        sa.Column("estimated_business_impact", sa.Float(), nullable=False),
        sa.Column("algorithm", sa.String(64), nullable=False),
        sa.Column("top_k", sa.Integer(), nullable=False),
        sa.Column("sample_size", sa.Integer(), nullable=False),
        sa.Column("approximation_mode", sa.String(64), nullable=False),
        sa.Column("simulation_seed", sa.Integer(), nullable=False),
        sa.Column("score_input_version", sa.Integer(), nullable=False),
        sa.Column("plan_steps_json", postgresql.JSONB(), nullable=False),
        sa.Column("metadata_json", postgresql.JSONB(), nullable=False),
        schema="remediation_impact",
    )
    op.create_index(
        "ix_exposure_reduction_plans_tenant_id",
        "exposure_reduction_plans",
        ["tenant_id"],
        schema="remediation_impact",
    )


def downgrade() -> None:
    op.drop_index(
        "ix_exposure_reduction_plans_tenant_id",
        table_name="exposure_reduction_plans",
        schema="remediation_impact",
    )
    op.drop_table("exposure_reduction_plans", schema="remediation_impact")
    op.execute("DROP SCHEMA IF EXISTS remediation_impact CASCADE")
