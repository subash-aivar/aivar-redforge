"""0156 — risk_engine foundation tables (M48E).

Migration chain: 0155 -> 0156.

Creates persistence for the two risk_engine aggregate roots
(`EnterpriseRiskProfile`, `RiskCorrelationSet`) plus their child
tables:

- risk_engine_profiles / risk_engine_profile_contributions /
  risk_engine_profile_score_history
- risk_engine_correlation_sets / risk_engine_correlation_signal_refs
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0156"
down_revision: str = "0155"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "risk_engine_profiles",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("subject_reference", sa.String(512), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accepted_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("composite_score_value", sa.Float(), nullable=True),
        sa.Column("composite_weight_profile_id", sa.String(256), nullable=True),
        sa.Column("composite_computed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
    )
    op.create_index("ix_risk_engine_profiles_tenant", "risk_engine_profiles", ["tenant_id"])
    op.create_index(
        "ix_risk_engine_profiles_tenant_status",
        "risk_engine_profiles",
        ["tenant_id", "status"],
    )
    op.create_index(
        "ix_risk_engine_profiles_tenant_subject",
        "risk_engine_profiles",
        ["tenant_id", "subject_reference"],
    )

    op.create_table(
        "risk_engine_profile_contributions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "profile_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("risk_engine_profiles.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("dimension", sa.String(64), nullable=False),
        sa.Column("normalized_score", sa.Float(), nullable=False),
        sa.Column("computed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("signal_tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("signal_source_context", sa.String(128), nullable=False),
        sa.Column("signal_source_aggregate_type", sa.String(128), nullable=False),
        sa.Column("signal_source_id", sa.String(256), nullable=False),
        sa.Column("signal_type", sa.String(64), nullable=False),
        sa.Column("signal_raw_value", sa.Float(), nullable=False),
        sa.Column("signal_raw_scale", sa.String(32), nullable=False),
        sa.Column("signal_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("signal_subject_reference", sa.String(512), nullable=True),
        sa.UniqueConstraint(
            "profile_id", "ordinal", name="uq_risk_engine_profile_contributions_ordinal"
        ),
    )
    op.create_index(
        "ix_risk_engine_profile_contributions_profile",
        "risk_engine_profile_contributions",
        ["profile_id"],
    )

    op.create_table(
        "risk_engine_profile_score_history",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "profile_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("risk_engine_profiles.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("value", sa.Float(), nullable=False),
        sa.Column("weight_profile_id", sa.String(256), nullable=False),
        sa.Column("computed_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "profile_id",
            "computed_at",
            name="uq_risk_engine_profile_score_history_profile_computed_at",
        ),
    )
    op.create_index(
        "ix_risk_engine_profile_score_history_profile",
        "risk_engine_profile_score_history",
        ["profile_id", "computed_at"],
    )
    op.create_index(
        "ix_risk_engine_profile_score_history_tenant",
        "risk_engine_profile_score_history",
        ["tenant_id"],
    )

    op.create_table(
        "risk_engine_correlation_sets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("formed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
    )
    op.create_index(
        "ix_risk_engine_correlation_sets_tenant", "risk_engine_correlation_sets", ["tenant_id"]
    )

    op.create_table(
        "risk_engine_correlation_signal_refs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "correlation_set_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("risk_engine_correlation_sets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("signal_tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("signal_source_context", sa.String(128), nullable=False),
        sa.Column("signal_source_aggregate_type", sa.String(128), nullable=False),
        sa.Column("signal_source_id", sa.String(256), nullable=False),
        sa.Column("signal_type", sa.String(64), nullable=False),
        sa.Column("signal_raw_value", sa.Float(), nullable=False),
        sa.Column("signal_raw_scale", sa.String(32), nullable=False),
        sa.Column("signal_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("signal_subject_reference", sa.String(512), nullable=True),
        sa.UniqueConstraint(
            "correlation_set_id",
            "ordinal",
            name="uq_risk_engine_correlation_signal_refs_ordinal",
        ),
    )
    op.create_index(
        "ix_risk_engine_correlation_signal_refs_set",
        "risk_engine_correlation_signal_refs",
        ["correlation_set_id"],
    )


def downgrade() -> None:
    op.drop_table("risk_engine_correlation_signal_refs")
    op.drop_table("risk_engine_correlation_sets")
    op.drop_table("risk_engine_profile_score_history")
    op.drop_table("risk_engine_profile_contributions")
    op.drop_table("risk_engine_profiles")
