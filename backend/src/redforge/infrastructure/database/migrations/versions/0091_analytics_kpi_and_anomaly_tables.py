"""0091 — M33 Phase 1 KPI snapshots, anomalies, processed events.

Migration chain: 0090 → 0091.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0091"
down_revision: str = "0090"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "kpi_snapshots",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("kpi_type", sa.String(64), nullable=False),
        sa.Column("value", sa.Float(), nullable=True),
        sa.Column("unit", sa.String(64), nullable=False),
        sa.Column("status", sa.String(64), nullable=False),
        sa.Column("definition_version", sa.Integer(), nullable=False),
        sa.Column("snapshot_at", sa.DateTime(timezone=True), nullable=False),
        schema="analytics",
    )
    op.create_index(
        "ix_kpi_snapshots_tenant_type_at",
        "kpi_snapshots",
        ["tenant_id", "kpi_type", "snapshot_at"],
        schema="analytics",
    )

    op.create_table(
        "anomaly_detections",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("signal_type", sa.String(64), nullable=False),
        sa.Column("method", sa.String(64), nullable=False),
        sa.Column("observed_value", sa.Float(), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("details_json", postgresql.JSONB(), nullable=False),
        schema="analytics",
    )
    op.create_index(
        "ix_anomaly_detections_tenant_at",
        "anomaly_detections",
        ["tenant_id", "detected_at"],
        schema="analytics",
    )

    op.create_table(
        "processed_analytics_events",
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_id", sa.String(256), nullable=False),
        sa.Column("domain", sa.String(64), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("tenant_id", "event_id", name="pk_processed_analytics_events"),
        schema="analytics",
    )

    op.create_table(
        "analytics_datasets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("domain", sa.String(64), nullable=False),
        sa.Column("schema_version", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("checkpoint_event_id", sa.String(256), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        schema="analytics",
    )
    op.create_index(
        "ix_analytics_datasets_tenant_domain",
        "analytics_datasets",
        ["tenant_id", "domain"],
        schema="analytics",
    )

    op.create_table(
        "security_kpis",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("kpi_type", sa.String(64), nullable=False),
        sa.Column("status", sa.String(64), nullable=False),
        sa.Column("computation_schedule_cron", sa.String(64), nullable=False),
        sa.Column("latest_value", sa.Float(), nullable=True),
        sa.Column("latest_unit", sa.String(64), nullable=True),
        sa.Column("definition_version", sa.Integer(), nullable=False),
        sa.Column("last_computed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "kpi_type", name="uq_security_kpi_tenant_type"),
        schema="analytics",
    )

    op.create_table(
        "anomaly_detection_baselines",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("signal_type", sa.String(64), nullable=False),
        sa.Column("method", sa.String(64), nullable=False),
        sa.Column("window_days", sa.Integer(), nullable=False),
        sa.Column("bootstrapped", sa.Boolean(), nullable=False),
        sa.Column("observation_count", sa.Integer(), nullable=False),
        sa.Column("params_json", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "tenant_id", "signal_type", "method", name="uq_anomaly_baseline_signal"
        ),
        schema="analytics",
    )

    op.create_table(
        "projection_checkpoints",
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("domain", sa.String(64), nullable=False),
        sa.Column("last_event_id", sa.String(256), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("tenant_id", "domain", name="pk_projection_checkpoints"),
        schema="analytics",
    )


def downgrade() -> None:
    for t in (
        "projection_checkpoints",
        "anomaly_detection_baselines",
        "security_kpis",
        "analytics_datasets",
        "processed_analytics_events",
        "anomaly_detections",
        "kpi_snapshots",
    ):
        op.drop_table(t, schema="analytics")
