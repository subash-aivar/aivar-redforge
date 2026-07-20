"""0061 — M28 Phase 4 DetectionPack, DetectionException, DetectionEvidence.

Creates pack/exception/evidence tables and pack rule/version tables only.
No Security Graph, reporting, or coverage materialized views.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0061"
down_revision: str = "0060"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_SCHEMA = "detection"


def upgrade() -> None:
    op.execute(sa.text(f"CREATE SCHEMA IF NOT EXISTS {_SCHEMA}"))

    op.create_table(
        "detection_packs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("pack_key", sa.String(length=128), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("lifecycle_state", sa.String(length=32), nullable=False),
        sa.Column("semver", sa.String(length=32), nullable=False),
        sa.Column("maintainer_json", postgresql.JSONB(), nullable=False),
        sa.Column("subscription_json", postgresql.JSONB(), nullable=False),
        sa.Column("compliance_framework_json", postgresql.JSONB(), nullable=True),
        sa.Column("coverage_json", postgresql.JSONB(), nullable=False),
        sa.Column("metadata_json", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="0"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_detection_packs_tenant_id",
        "detection_packs",
        ["tenant_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_detection_packs_tenant_key",
        "detection_packs",
        ["tenant_id", "pack_key"],
        unique=True,
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_detection_packs_tenant_state",
        "detection_packs",
        ["tenant_id", "lifecycle_state"],
        schema=_SCHEMA,
    )

    op.create_table(
        "detection_pack_rules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("pack_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("rule_version", sa.String(length=32), nullable=True),
        sa.Column("optional", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["pack_id"],
            [f"{_SCHEMA}.detection_packs.id"],
            ondelete="CASCADE",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_detection_pack_rules_pack",
        "detection_pack_rules",
        ["pack_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_detection_pack_rules_tenant_rule",
        "detection_pack_rules",
        ["tenant_id", "rule_id"],
        schema=_SCHEMA,
    )

    op.create_table(
        "detection_pack_versions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("pack_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("rule_snapshots_json", postgresql.JSONB(), nullable=False),
        sa.Column("release_notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["pack_id"],
            [f"{_SCHEMA}.detection_packs.id"],
            ondelete="CASCADE",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_detection_pack_versions_pack",
        "detection_pack_versions",
        ["pack_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_detection_pack_versions_tenant",
        "detection_pack_versions",
        ["tenant_id"],
        schema=_SCHEMA,
    )

    op.create_table(
        "detection_exceptions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("exception_type", sa.String(length=64), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("scope_json", postgresql.JSONB(), nullable=False),
        sa.Column("justification_json", postgresql.JSONB(), nullable=False),
        sa.Column("requester", sa.String(length=256), nullable=False),
        sa.Column("approver", sa.String(length=256), nullable=True),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("affected_rules_json", postgresql.JSONB(), nullable=False),
        sa.Column("asset_scope_json", postgresql.JSONB(), nullable=True),
        sa.Column(
            "compliance_impact_acknowledged",
            sa.Boolean(),
            nullable=False,
            server_default="false",
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="0"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_detection_exceptions_tenant_id",
        "detection_exceptions",
        ["tenant_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_detection_exceptions_tenant_state",
        "detection_exceptions",
        ["tenant_id", "state"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_detection_exceptions_tenant_valid_until",
        "detection_exceptions",
        ["tenant_id", "valid_until"],
        schema=_SCHEMA,
    )

    op.create_table(
        "detection_evidence",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("evidence_type", sa.String(length=64), nullable=False),
        sa.Column("payload_hash", sa.String(length=64), nullable=False),
        sa.Column("storage_ref", sa.String(length=2048), nullable=False),
        sa.Column("collected_by", sa.String(length=256), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("integrity_status", sa.String(length=32), nullable=False),
        sa.Column("finding_id", sa.String(length=64), nullable=True),
        sa.Column("exception_id", sa.String(length=64), nullable=True),
        sa.Column("simulation_id", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="0"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_detection_evidence_tenant_id",
        "detection_evidence",
        ["tenant_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_detection_evidence_tenant_finding",
        "detection_evidence",
        ["tenant_id", "finding_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_detection_evidence_tenant_exception",
        "detection_evidence",
        ["tenant_id", "exception_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_detection_evidence_tenant_hash",
        "detection_evidence",
        ["tenant_id", "payload_hash"],
        schema=_SCHEMA,
    )


def downgrade() -> None:
    op.drop_table("detection_evidence", schema=_SCHEMA)
    op.drop_table("detection_exceptions", schema=_SCHEMA)
    op.drop_table("detection_pack_versions", schema=_SCHEMA)
    op.drop_table("detection_pack_rules", schema=_SCHEMA)
    op.drop_table("detection_packs", schema=_SCHEMA)
