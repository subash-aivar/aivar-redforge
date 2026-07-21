"""0073 — M30 Phase 3 campaignexecution bounded context foundation.

Creates the campaignexecution schema with tables for:
- task_graph_executions (TaskGraphExecution aggregate)
- task_execution_records (TaskExecutionRecord entities)
- campaign_safety_monitors (CampaignSafetyMonitor aggregate)

Migration chain: 0072 (taskgraph foundation) → 0073 (campaignexecution foundation).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0073"
down_revision: str = "0072"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS campaignexecution")

    # ── task_graph_executions ─────────────────────────────────────────────────
    op.create_table(
        "task_graph_executions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("campaign_instance_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("campaign_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("graph_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("graph_version", sa.String(32), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column(
            "policy_snapshot_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column(
            "pending_approval_gate_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column(
            "objective_states_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        schema="campaignexecution",
    )
    op.create_index(
        "ix_tge_tenant_id",
        "task_graph_executions",
        ["tenant_id"],
        schema="campaignexecution",
    )
    op.create_index(
        "ix_tge_campaign_instance_id",
        "task_graph_executions",
        ["campaign_instance_id"],
        schema="campaignexecution",
    )
    op.create_index(
        "ix_tge_state",
        "task_graph_executions",
        ["state"],
        schema="campaignexecution",
    )

    # ── task_execution_records ────────────────────────────────────────────────
    op.create_table(
        "task_execution_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "execution_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(
                "campaignexecution.task_graph_executions.id",
                ondelete="CASCADE",
            ),
            nullable=False,
        ),
        sa.Column("task_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("outcome", sa.String(32), nullable=True),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("operation_tenant_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("dispatched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        sa.Column(
            "is_rollback_task",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        schema="campaignexecution",
    )
    op.create_index(
        "ix_ter_execution_id",
        "task_execution_records",
        ["execution_id"],
        schema="campaignexecution",
    )
    op.create_index(
        "ix_ter_task_id",
        "task_execution_records",
        ["task_id"],
        schema="campaignexecution",
    )
    op.create_index(
        "ix_ter_state",
        "task_execution_records",
        ["state"],
        schema="campaignexecution",
    )

    # ── campaign_safety_monitors ──────────────────────────────────────────────
    op.create_table(
        "campaign_safety_monitors",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "campaign_instance_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            unique=True,
        ),
        sa.Column("campaign_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("monitor_state", sa.String(32), nullable=False),
        sa.Column(
            "auto_abort_triggered",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "active_operation_ids_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="[]",
        ),
        sa.Column(
            "policy_snapshot_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        schema="campaignexecution",
    )
    op.create_index(
        "ix_csm_tenant_id",
        "campaign_safety_monitors",
        ["tenant_id"],
        schema="campaignexecution",
    )
    op.create_index(
        "ix_csm_campaign_instance_id",
        "campaign_safety_monitors",
        ["campaign_instance_id"],
        schema="campaignexecution",
    )


def downgrade() -> None:
    op.drop_table("task_execution_records", schema="campaignexecution")
    op.drop_table("campaign_safety_monitors", schema="campaignexecution")
    op.drop_table("task_graph_executions", schema="campaignexecution")
    op.execute("DROP SCHEMA IF EXISTS campaignexecution CASCADE")
