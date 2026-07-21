"""0081 — M32 Phase 1 exposure foundation.

Creates exposure schema and tables corresponding to frozen plan migrations
0041-0045 (mapped onto the live Alembic chain after M31 head 0080):
- exposure_records (+ embedded amplifiers JSON)
- exposure_score_snapshots
- amplifier_weight_configurations
- pending_recomputations
- processed_exposure_signals
- tenant_exposure_profiles (TenantExposureProfile read model)

Migration chain: 0080 → 0081.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0081"
down_revision: str = "0080"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS exposure")

    op.create_table(
        "exposure_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_ref_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("signal_domain", sa.String(64), nullable=False),
        sa.Column("signal_source_ref", sa.String(256), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("base_exposure_level", sa.Float(), nullable=False),
        sa.Column("current_exposure_score", sa.Float(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("suppression_justification", sa.Text(), nullable=True),
        sa.Column("amplifiers_json", postgresql.JSONB(), nullable=False),
        sa.Column("technique_refs_json", postgresql.JSONB(), nullable=False),
        sa.UniqueConstraint(
            "tenant_id",
            "asset_ref_id",
            "signal_domain",
            "signal_source_ref",
            name="uq_exposure_identity",
        ),
        schema="exposure",
    )
    op.create_index(
        "ix_exposure_records_tenant_id",
        "exposure_records",
        ["tenant_id"],
        schema="exposure",
    )
    op.create_index(
        "ix_exposure_records_asset_ref_id",
        "exposure_records",
        ["asset_ref_id"],
        schema="exposure",
    )

    op.create_table(
        "exposure_score_snapshots",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_ref_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("composite_score", sa.Float(), nullable=False),
        sa.Column("score_input_version", sa.Integer(), nullable=False),
        sa.Column("computed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("job_id", sa.String(128), nullable=False),
        sa.Column("record_scores_json", postgresql.JSONB(), nullable=False),
        schema="exposure",
    )
    op.create_index(
        "ix_exposure_snapshots_tenant_asset_computed",
        "exposure_score_snapshots",
        ["tenant_id", "asset_ref_id", "computed_at"],
        schema="exposure",
    )

    op.create_table(
        "amplifier_weight_configurations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("weights_json", postgresql.JSONB(), nullable=False),
        sa.Column("change_rationale", sa.Text(), nullable=False),
        sa.Column("changed_by", sa.String(256), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "version", name="uq_weight_version"),
        schema="exposure",
    )

    op.create_table(
        "pending_recomputations",
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("asset_ref_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("marked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("debounce_override_seconds", sa.Integer(), nullable=True),
        sa.Column("bypass_debounce", sa.Boolean(), nullable=False, server_default="false"),
        schema="exposure",
    )

    op.create_table(
        "processed_exposure_signals",
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("event_id", sa.String(256), primary_key=True),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=False),
        schema="exposure",
    )

    op.create_table(
        "tenant_exposure_profiles",
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("asset_scores_json", postgresql.JSONB(), nullable=False),
        sa.Column("recomputing", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("recomputation_failed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata_json", postgresql.JSONB(), nullable=False),
        schema="exposure",
    )


def downgrade() -> None:
    op.drop_table("tenant_exposure_profiles", schema="exposure")
    op.drop_table("processed_exposure_signals", schema="exposure")
    op.drop_table("pending_recomputations", schema="exposure")
    op.drop_table("amplifier_weight_configurations", schema="exposure")
    op.drop_index(
        "ix_exposure_snapshots_tenant_asset_computed",
        table_name="exposure_score_snapshots",
        schema="exposure",
    )
    op.drop_table("exposure_score_snapshots", schema="exposure")
    op.drop_index(
        "ix_exposure_records_asset_ref_id", table_name="exposure_records", schema="exposure"
    )
    op.drop_index("ix_exposure_records_tenant_id", table_name="exposure_records", schema="exposure")
    op.drop_table("exposure_records", schema="exposure")
    op.execute("DROP SCHEMA IF EXISTS exposure")
