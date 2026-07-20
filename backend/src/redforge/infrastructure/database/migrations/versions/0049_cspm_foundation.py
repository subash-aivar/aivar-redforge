"""0049 — M26 Phase 4 CSPM foundation (policies, findings, evaluations, drift)."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0049"
down_revision: str = "0048"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_SCHEMA = "cloud_security"


def upgrade() -> None:
    op.create_table(
        "cspm_policies",
        sa.Column("id", sa.String(length=128), primary_key=True),
        sa.Column("rule_id", sa.String(length=128), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("version", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("provider_types", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("asset_types", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("remediation", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "compliance_mapping", postgresql.JSONB(astext_type=sa.Text()), nullable=False
        ),
        sa.Column("rule", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("inherits_from", sa.String(length=128), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column(
            "evaluation_strategy",
            sa.String(length=64),
            nullable=False,
            server_default="boolean",
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cspm_policies_enabled",
        "cspm_policies",
        ["enabled"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cspm_policies_rule_id",
        "cspm_policies",
        ["rule_id"],
        schema=_SCHEMA,
    )

    op.create_table(
        "cspm_findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", sa.String(length=26), nullable=False),
        sa.Column("cloud_asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("policy_id", sa.String(length=128), nullable=False),
        sa.Column("rule_id", sa.String(length=128), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("remediation", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "compliance_mapping", postgresql.JSONB(astext_type=sa.Text()), nullable=False
        ),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("history", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reopened_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("suppressed_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("accepted_by", sa.String(length=256), nullable=True),
        sa.Column("accepted_reason", sa.Text(), nullable=True),
        sa.Column("config_hash", sa.String(length=128), nullable=False),
        sa.Column("fingerprint", sa.String(length=512), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "organization_id",
            "fingerprint",
            name="uq_cspm_findings_org_fingerprint",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cspm_findings_org_status",
        "cspm_findings",
        ["organization_id", "status"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cspm_findings_cloud_asset_id",
        "cspm_findings",
        ["cloud_asset_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cspm_findings_organization_id",
        "cspm_findings",
        ["organization_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cspm_findings_policy_id",
        "cspm_findings",
        ["policy_id"],
        schema=_SCHEMA,
    )

    op.create_table(
        "cspm_evaluations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", sa.String(length=26), nullable=False),
        sa.Column("cloud_account_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("context", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("results", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("assets_evaluated", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("policies_evaluated", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings_opened", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings_resolved", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("diagnostics", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cspm_evaluations_org_status",
        "cspm_evaluations",
        ["organization_id", "status"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cspm_evaluations_organization_id",
        "cspm_evaluations",
        ["organization_id"],
        schema=_SCHEMA,
    )

    op.create_table(
        "cspm_drift_baselines",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", sa.String(length=26), nullable=False),
        sa.Column("cloud_asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("drift_kind", sa.String(length=64), nullable=False),
        sa.Column("baseline_hash", sa.String(length=128), nullable=False),
        sa.Column(
            "baseline_snapshot", postgresql.JSONB(astext_type=sa.Text()), nullable=False
        ),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "organization_id",
            "cloud_asset_id",
            "drift_kind",
            name="uq_cspm_drift_baselines_org_asset_kind",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cspm_drift_baselines_organization_id",
        "cspm_drift_baselines",
        ["organization_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cspm_drift_baselines_cloud_asset_id",
        "cspm_drift_baselines",
        ["cloud_asset_id"],
        schema=_SCHEMA,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_cspm_drift_baselines_cloud_asset_id",
        table_name="cspm_drift_baselines",
        schema=_SCHEMA,
    )
    op.drop_index(
        "ix_cspm_drift_baselines_organization_id",
        table_name="cspm_drift_baselines",
        schema=_SCHEMA,
    )
    op.drop_table("cspm_drift_baselines", schema=_SCHEMA)

    op.drop_index(
        "ix_cspm_evaluations_organization_id",
        table_name="cspm_evaluations",
        schema=_SCHEMA,
    )
    op.drop_index(
        "ix_cspm_evaluations_org_status",
        table_name="cspm_evaluations",
        schema=_SCHEMA,
    )
    op.drop_table("cspm_evaluations", schema=_SCHEMA)

    op.drop_index(
        "ix_cspm_findings_policy_id",
        table_name="cspm_findings",
        schema=_SCHEMA,
    )
    op.drop_index(
        "ix_cspm_findings_organization_id",
        table_name="cspm_findings",
        schema=_SCHEMA,
    )
    op.drop_index(
        "ix_cspm_findings_cloud_asset_id",
        table_name="cspm_findings",
        schema=_SCHEMA,
    )
    op.drop_index(
        "ix_cspm_findings_org_status",
        table_name="cspm_findings",
        schema=_SCHEMA,
    )
    op.drop_table("cspm_findings", schema=_SCHEMA)

    op.drop_index(
        "ix_cspm_policies_rule_id",
        table_name="cspm_policies",
        schema=_SCHEMA,
    )
    op.drop_index(
        "ix_cspm_policies_enabled",
        table_name="cspm_policies",
        schema=_SCHEMA,
    )
    op.drop_table("cspm_policies", schema=_SCHEMA)
