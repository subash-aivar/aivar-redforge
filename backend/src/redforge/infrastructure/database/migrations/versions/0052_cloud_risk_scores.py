"""0052 — M26 Phase 7 Cloud Risk Correlation Engine tables.

Stores current risk scores (unique per org+asset), append-only history,
factors, exposures, and assessment run records under cloud_security.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0052"
down_revision: str = "0051"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_SCHEMA = "cloud_security"


def upgrade() -> None:
    op.create_table(
        "cloud_risk_scores",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", sa.String(length=26), nullable=False),
        sa.Column("cloud_asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("overall_score", sa.Float(), nullable=False),
        sa.Column("threat_intel_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("compliance_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("identity_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("exposure_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("business_criticality_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("attack_path_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("cspm_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("kubernetes_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("runtime_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("score_components", postgresql.JSONB(), nullable=False),
        sa.Column("evidence", postgresql.JSONB(), nullable=False),
        sa.Column("history", postgresql.JSONB(), nullable=False),
        sa.Column("exceptions", postgresql.JSONB(), nullable=False),
        sa.Column("weight_profile", postgresql.JSONB(), nullable=False),
        sa.Column("calculation_version", postgresql.JSONB(), nullable=False),
        sa.Column("confidence", sa.String(length=32), nullable=False),
        sa.Column("trend", sa.String(length=32), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("threshold", sa.Float(), nullable=False, server_default="7"),
        sa.Column("computed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "organization_id",
            "cloud_asset_id",
            name="uq_cloud_risk_scores_org_asset",
        ),
        schema=_SCHEMA,
    )
    op.execute(
        sa.text(
            f"CREATE INDEX ix_cloud_risk_scores_org_overall "
            f"ON {_SCHEMA}.cloud_risk_scores (organization_id, overall_score DESC)"
        )
    )
    op.create_index(
        "ix_cloud_risk_scores_cloud_asset_id",
        "cloud_risk_scores",
        ["cloud_asset_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cloud_risk_scores_state",
        "cloud_risk_scores",
        ["state"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cloud_risk_scores_organization_id",
        "cloud_risk_scores",
        ["organization_id"],
        schema=_SCHEMA,
    )

    op.create_table(
        "cloud_risk_history",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", sa.String(length=26), nullable=False),
        sa.Column("cloud_asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("risk_score_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("overall_score", sa.Float(), nullable=False),
        sa.Column("dimensions", postgresql.JSONB(), nullable=False),
        sa.Column("calculation_version", sa.String(length=128), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reason", sa.String(length=512), nullable=False, server_default=""),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cloud_risk_history_org_asset",
        "cloud_risk_history",
        ["organization_id", "cloud_asset_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cloud_risk_history_risk_score_id",
        "cloud_risk_history",
        ["risk_score_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cloud_risk_history_recorded_at",
        "cloud_risk_history",
        ["recorded_at"],
        schema=_SCHEMA,
    )

    op.create_table(
        "cloud_risk_factors",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", sa.String(length=26), nullable=False),
        sa.Column("cloud_asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.String(length=32), nullable=False),
        sa.Column("evidence", postgresql.JSONB(), nullable=False),
        sa.Column("metadata", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cloud_risk_factors_org_asset",
        "cloud_risk_factors",
        ["organization_id", "cloud_asset_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cloud_risk_factors_organization_id",
        "cloud_risk_factors",
        ["organization_id"],
        schema=_SCHEMA,
    )

    op.create_table(
        "cloud_risk_exposures",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", sa.String(length=26), nullable=False),
        sa.Column("cloud_asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("public_accessibility", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("internet_exposure", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("encryption_at_rest", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("privilege_level", sa.String(length=32), nullable=False, server_default="NONE"),
        sa.Column(
            "lateral_movement_potential",
            sa.String(length=64),
            nullable=False,
            server_default="UNKNOWN",
        ),
        sa.Column("exposure_score", sa.Float(), nullable=False),
        sa.Column("details", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "organization_id",
            "cloud_asset_id",
            name="uq_cloud_risk_exposures_org_asset",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cloud_risk_exposures_organization_id",
        "cloud_risk_exposures",
        ["organization_id"],
        schema=_SCHEMA,
    )

    op.create_table(
        "cloud_risk_assessments",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", sa.String(length=26), nullable=False),
        sa.Column("scope", sa.String(length=32), nullable=False),
        sa.Column("target_id", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("assets_evaluated", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("risks_created", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("risks_updated", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("calculation_version", sa.String(length=128), nullable=False),
        sa.Column("diagnostics", postgresql.JSONB(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cloud_risk_assessments_organization_id",
        "cloud_risk_assessments",
        ["organization_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cloud_risk_assessments_status",
        "cloud_risk_assessments",
        ["status"],
        schema=_SCHEMA,
    )


def downgrade() -> None:
    op.drop_table("cloud_risk_assessments", schema=_SCHEMA)
    op.drop_table("cloud_risk_exposures", schema=_SCHEMA)
    op.drop_table("cloud_risk_factors", schema=_SCHEMA)
    op.drop_table("cloud_risk_history", schema=_SCHEMA)
    op.drop_table("cloud_risk_scores", schema=_SCHEMA)
