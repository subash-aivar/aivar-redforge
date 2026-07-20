"""0060 — M28 Phase 3 DetectionExecution + DetectionFinding.

Creates detection_executions and detection_findings tables only.
No packs, exceptions, evidence, correlation tables, or Security Graph.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0060"
down_revision: str = "0059"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_SCHEMA = "detection"


def upgrade() -> None:
    op.execute(sa.text(f"CREATE SCHEMA IF NOT EXISTS {_SCHEMA}"))

    op.create_table(
        "detection_executions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("rule_version", sa.String(length=32), nullable=True),
        sa.Column("source_id", sa.String(length=64), nullable=False),
        sa.Column("source_type", sa.String(length=64), nullable=True),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("trigger", sa.String(length=32), nullable=False),
        sa.Column("stats_json", postgresql.JSONB(), nullable=False),
        sa.Column("error_json", postgresql.JSONB(), nullable=True),
        sa.Column("finding_refs_json", postgresql.JSONB(), nullable=False),
        sa.Column("scheduled_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="0"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_detection_executions_tenant_id",
        "detection_executions",
        ["tenant_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_detection_executions_tenant_state",
        "detection_executions",
        ["tenant_id", "state"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_detection_executions_tenant_rule",
        "detection_executions",
        ["tenant_id", "rule_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_detection_executions_tenant_started",
        "detection_executions",
        ["tenant_id", "started_at"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_detection_executions_tenant_scheduled",
        "detection_executions",
        ["tenant_id", "scheduled_at"],
        schema=_SCHEMA,
    )

    op.create_table(
        "detection_findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("finding_key", sa.String(length=64), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("rule_version", sa.String(length=32), nullable=True),
        sa.Column("execution_id", sa.String(length=64), nullable=False),
        sa.Column("asset_id", sa.String(length=256), nullable=False),
        sa.Column("asset_type", sa.String(length=64), nullable=True),
        sa.Column("signal_id", sa.String(length=256), nullable=False),
        sa.Column("signal_source_id", sa.String(length=64), nullable=True),
        sa.Column("telemetry_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.String(length=32), nullable=False),
        sa.Column("state", sa.String(length=48), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("mitre_json", postgresql.JSONB(), nullable=True),
        sa.Column("correlation_json", postgresql.JSONB(), nullable=False),
        sa.Column("analyst_note_json", postgresql.JSONB(), nullable=True),
        sa.Column("escalation_json", postgresql.JSONB(), nullable=True),
        sa.Column("reopened_from", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="0"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_detection_findings_tenant_id",
        "detection_findings",
        ["tenant_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_detection_findings_tenant_key",
        "detection_findings",
        ["tenant_id", "finding_key"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_detection_findings_tenant_state",
        "detection_findings",
        ["tenant_id", "state"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_detection_findings_tenant_asset",
        "detection_findings",
        ["tenant_id", "asset_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_detection_findings_tenant_rule",
        "detection_findings",
        ["tenant_id", "rule_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_detection_findings_tenant_detected",
        "detection_findings",
        ["tenant_id", "detected_at"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_detection_findings_tenant_last_seen",
        "detection_findings",
        ["tenant_id", "last_seen_at"],
        schema=_SCHEMA,
    )


def downgrade() -> None:
    for name in (
        "ix_detection_findings_tenant_last_seen",
        "ix_detection_findings_tenant_detected",
        "ix_detection_findings_tenant_rule",
        "ix_detection_findings_tenant_asset",
        "ix_detection_findings_tenant_state",
        "ix_detection_findings_tenant_key",
        "ix_detection_findings_tenant_id",
    ):
        op.drop_index(name, table_name="detection_findings", schema=_SCHEMA)
    op.drop_table("detection_findings", schema=_SCHEMA)

    for name in (
        "ix_detection_executions_tenant_scheduled",
        "ix_detection_executions_tenant_started",
        "ix_detection_executions_tenant_rule",
        "ix_detection_executions_tenant_state",
        "ix_detection_executions_tenant_id",
    ):
        op.drop_index(name, table_name="detection_executions", schema=_SCHEMA)
    op.drop_table("detection_executions", schema=_SCHEMA)
