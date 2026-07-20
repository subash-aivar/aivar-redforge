"""0058 — M28 Phase 1 Detection Rule foundation.

Creates schema detection with detection_rules and owned child tables.
No packs, telemetry sources, executions, findings, or exceptions.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0058"
down_revision: str = "0057"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_SCHEMA = "detection"


def upgrade() -> None:
    op.execute(sa.text(f"CREATE SCHEMA IF NOT EXISTS {_SCHEMA}"))

    op.create_table(
        "detection_rules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("rule_key", sa.String(length=256), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.String(length=32), nullable=False),
        sa.Column("lifecycle_state", sa.String(length=32), nullable=False),
        sa.Column("author_identity", sa.String(length=256), nullable=False),
        sa.Column("reviewer_identity", sa.String(length=256), nullable=True),
        sa.Column("current_logic_json", postgresql.JSONB(), nullable=False),
        sa.Column("telemetry_sources_json", postgresql.JSONB(), nullable=False),
        sa.Column("asset_scope_json", postgresql.JSONB(), nullable=True),
        sa.Column("throttle_json", postgresql.JSONB(), nullable=True),
        sa.Column("fp_profile_json", postgresql.JSONB(), nullable=True),
        sa.Column("tags_json", postgresql.JSONB(), nullable=False),
        sa.Column("external_refs_json", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "tenant_id", "rule_key", name="uq_detection_rules_tenant_key"
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_detection_rules_tenant_id", "detection_rules", ["tenant_id"], schema=_SCHEMA
    )
    op.create_index(
        "ix_detection_rules_tenant_lifecycle",
        "detection_rules",
        ["tenant_id", "lifecycle_state"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_detection_rules_tenant_category",
        "detection_rules",
        ["tenant_id", "category"],
        schema=_SCHEMA,
    )

    op.create_table(
        "rule_versions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("rule_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("semver", sa.String(length=32), nullable=False),
        sa.Column("logic_json", postgresql.JSONB(), nullable=False),
        sa.Column("change_summary", sa.Text(), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("published_by", sa.String(length=256), nullable=False),
        sa.ForeignKeyConstraint(
            ["rule_id"],
            [f"{_SCHEMA}.detection_rules.id"],
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("rule_id", "semver", name="uq_rule_versions_rule_semver"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_rule_versions_tenant_id", "rule_versions", ["tenant_id"], schema=_SCHEMA
    )
    op.create_index(
        "ix_rule_versions_rule_id", "rule_versions", ["rule_id"], schema=_SCHEMA
    )

    op.create_table(
        "rule_test_cases",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("rule_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("input_payload_json", postgresql.JSONB(), nullable=False),
        sa.Column("expected_match", sa.Boolean(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["rule_id"],
            [f"{_SCHEMA}.detection_rules.id"],
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("rule_id", "name", name="uq_rule_test_cases_rule_name"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_rule_test_cases_rule_id", "rule_test_cases", ["rule_id"], schema=_SCHEMA
    )
    op.create_index(
        "ix_rule_test_cases_tenant_id", "rule_test_cases", ["tenant_id"], schema=_SCHEMA
    )

    op.create_table(
        "rule_test_results",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("rule_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("test_case_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("rule_version", sa.String(length=32), nullable=True),
        sa.ForeignKeyConstraint(
            ["rule_id"],
            [f"{_SCHEMA}.detection_rules.id"],
            ondelete="CASCADE",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_rule_test_results_rule_id", "rule_test_results", ["rule_id"], schema=_SCHEMA
    )
    op.create_index(
        "ix_rule_test_results_tenant_id",
        "rule_test_results",
        ["tenant_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_rule_test_results_test_case_id",
        "rule_test_results",
        ["test_case_id"],
        schema=_SCHEMA,
    )

    op.create_table(
        "rule_mitre_mappings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("rule_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tactic", sa.String(length=128), nullable=False),
        sa.Column("technique", sa.String(length=32), nullable=False),
        sa.Column("sub_technique", sa.String(length=32), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("weight", sa.Float(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(
            ["rule_id"],
            [f"{_SCHEMA}.detection_rules.id"],
            ondelete="CASCADE",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_rule_mitre_rule_id", "rule_mitre_mappings", ["rule_id"], schema=_SCHEMA
    )
    op.create_index(
        "ix_rule_mitre_tenant_technique",
        "rule_mitre_mappings",
        ["tenant_id", "technique"],
        schema=_SCHEMA,
    )


def downgrade() -> None:
    for table in (
        "rule_mitre_mappings",
        "rule_test_results",
        "rule_test_cases",
        "rule_versions",
        "detection_rules",
    ):
        op.drop_table(table, schema=_SCHEMA)
    op.execute(sa.text(f"DROP SCHEMA IF EXISTS {_SCHEMA}"))
