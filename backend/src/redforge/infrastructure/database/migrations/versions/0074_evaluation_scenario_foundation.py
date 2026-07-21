"""0074 — M30 Phase 5 evaluation + scenario bounded context foundation.

Creates:
- evaluation schema: campaign_evaluations, campaign_metrics_snapshots
- scenario schema: scenario_templates

Migration chain: 0073 (campaignexecution) → 0074 (evaluation + scenario).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0074"
down_revision: str = "0073"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS evaluation")
    op.execute("CREATE SCHEMA IF NOT EXISTS scenario")

    op.create_table(
        "campaign_evaluations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("campaign_instance_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("campaign_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("run_number", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("composite_outcome", sa.String(32), nullable=True),
        sa.Column("execution_failed", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("correlation_window_minutes", sa.Integer(), nullable=False),
        sa.Column("objective_specs_json", postgresql.JSONB(), nullable=False),
        sa.Column("assessments_json", postgresql.JSONB(), nullable=False),
        sa.Column("technique_outcomes_json", postgresql.JSONB(), nullable=False),
        sa.Column("late_detections_json", postgresql.JSONB(), nullable=False),
        sa.Column("metrics_json", postgresql.JSONB(), nullable=False),
        sa.Column("kill_chain_json", postgresql.JSONB(), nullable=True),
        sa.Column("compliance_mappings_json", postgresql.JSONB(), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        schema="evaluation",
    )
    op.create_index(
        "ix_campaign_evaluations_tenant_id",
        "campaign_evaluations",
        ["tenant_id"],
        schema="evaluation",
    )
    op.create_index(
        "ix_campaign_evaluations_state",
        "campaign_evaluations",
        ["state"],
        schema="evaluation",
    )
    op.create_index(
        "uq_campaign_evaluations_instance",
        "campaign_evaluations",
        ["campaign_instance_id"],
        unique=True,
        schema="evaluation",
    )

    op.create_table(
        "campaign_metrics_snapshots",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("campaign_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("run_number", sa.Integer(), nullable=False),
        sa.Column("snapshot_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("composite_outcome", sa.String(32), nullable=False),
        sa.Column("detection_coverage_percent", sa.Float(), nullable=False),
        sa.Column("technique_success_rate", sa.Float(), nullable=False),
        sa.Column("evasion_rate", sa.Float(), nullable=False),
        sa.Column("mean_time_to_detect_seconds", sa.Float(), nullable=True),
        sa.Column("objectives_achieved_count", sa.Integer(), nullable=False),
        sa.Column("objectives_failed_count", sa.Integer(), nullable=False),
        sa.Column("actions_executed_count", sa.Integer(), nullable=False),
        sa.Column("actions_failed_count", sa.Integer(), nullable=False),
        sa.Column("campaign_duration_seconds", sa.Float(), nullable=True),
        sa.Column("kill_chain_phases_covered_json", postgresql.JSONB(), nullable=False),
        sa.Column("metrics_json", postgresql.JSONB(), nullable=False),
        schema="evaluation",
    )
    op.create_index(
        "ix_metrics_snapshots_tenant_id",
        "campaign_metrics_snapshots",
        ["tenant_id"],
        schema="evaluation",
    )
    op.create_index(
        "ix_metrics_snapshots_campaign_id",
        "campaign_metrics_snapshots",
        ["campaign_id"],
        schema="evaluation",
    )

    op.create_table(
        "scenario_templates",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scenario_key", sa.String(256), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("version", sa.String(32), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("threat_actor_json", postgresql.JSONB(), nullable=True),
        sa.Column("covered_techniques_json", postgresql.JSONB(), nullable=False),
        sa.Column("parameters_json", postgresql.JSONB(), nullable=False),
        sa.Column("phases_json", postgresql.JSONB(), nullable=False),
        sa.Column("objective_blueprints_json", postgresql.JSONB(), nullable=False),
        sa.Column("default_safety_policy_json", postgresql.JSONB(), nullable=False),
        sa.Column("task_graph_blueprint_json", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        schema="scenario",
    )
    op.create_index(
        "ix_scenario_templates_tenant_id",
        "scenario_templates",
        ["tenant_id"],
        schema="scenario",
    )
    op.create_index(
        "ix_scenario_templates_scenario_key",
        "scenario_templates",
        ["scenario_key"],
        schema="scenario",
    )
    op.create_index(
        "ix_scenario_templates_state",
        "scenario_templates",
        ["state"],
        schema="scenario",
    )


def downgrade() -> None:
    op.drop_table("scenario_templates", schema="scenario")
    op.drop_table("campaign_metrics_snapshots", schema="evaluation")
    op.drop_table("campaign_evaluations", schema="evaluation")
    op.execute("DROP SCHEMA IF EXISTS scenario")
    op.execute("DROP SCHEMA IF EXISTS evaluation")
