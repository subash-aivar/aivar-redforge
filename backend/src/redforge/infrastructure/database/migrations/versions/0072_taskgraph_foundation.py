"""0072 — M30 Phase 2 taskgraph bounded context foundation.

Creates the taskgraph schema with tables for task graphs, campaign tasks,
and task dependencies.

Migration chain: 0071 (campaign foundation) → 0072 (taskgraph foundation).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0072"
down_revision: str = "0071"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_SCHEMA = "taskgraph"


def upgrade() -> None:
    op.execute(sa.text(f"CREATE SCHEMA IF NOT EXISTS {_SCHEMA}"))

    # task_graphs — TaskGraph aggregate root
    op.create_table(
        "task_graphs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=512), nullable=False),
        sa.Column("description", sa.String(length=2048), nullable=False, server_default=""),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("version_major", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("version_minor", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("version_patch", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("engagement_window_seconds", sa.Integer(), nullable=False),
        sa.Column("signed_by", sa.String(length=256), nullable=True),
        sa.Column("signed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("signature", sa.String(length=1024), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_taskgraph_task_graphs_tenant",
        "task_graphs",
        ["tenant_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_taskgraph_task_graphs_tenant_state",
        "task_graphs",
        ["tenant_id", "state"],
        schema=_SCHEMA,
    )
    # Unique constraint: only one Active graph per tenant per graph id
    # (enforced in application layer but this unique index prevents duplicates at DB level)
    op.create_index(
        "ix_taskgraph_task_graphs_tenant_name",
        "task_graphs",
        ["tenant_id", "name"],
        schema=_SCHEMA,
    )

    # campaign_tasks — CampaignTask entities (nodes in the task graph)
    op.create_table(
        "campaign_tasks",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "graph_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(f"{_SCHEMA}.task_graphs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("task_type", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=512), nullable=False),
        sa.Column("criticality", sa.String(length=32), nullable=False),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False),
        sa.Column(
            "operation_template_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column(
            "human_approval_config_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column(
            "barrier_policy_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column(
            "rollback_config_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column("task_group_id", sa.String(length=128), nullable=True),
        sa.Column("rollback_task_ref_id", postgresql.UUID(as_uuid=True), nullable=True),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_taskgraph_campaign_tasks_graph",
        "campaign_tasks",
        ["graph_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_taskgraph_campaign_tasks_tenant",
        "campaign_tasks",
        ["tenant_id"],
        schema=_SCHEMA,
    )

    # task_dependencies — TaskDependency entities (directed edges)
    op.create_table(
        "task_dependencies",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "graph_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(f"{_SCHEMA}.task_graphs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("predecessor_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("successor_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("predicate", sa.String(length=64), nullable=False),
        sa.Column("objective_ref", sa.String(length=128), nullable=True),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_taskgraph_task_dependencies_graph",
        "task_dependencies",
        ["graph_id"],
        schema=_SCHEMA,
    )
    op.create_unique_constraint(
        "uq_taskgraph_task_dependencies_edge",
        "task_dependencies",
        ["graph_id", "predecessor_id", "successor_id"],
        schema=_SCHEMA,
    )


def downgrade() -> None:
    op.drop_table("task_dependencies", schema=_SCHEMA)
    op.drop_table("campaign_tasks", schema=_SCHEMA)
    op.drop_table("task_graphs", schema=_SCHEMA)
    op.execute(sa.text(f"DROP SCHEMA IF EXISTS {_SCHEMA}"))
