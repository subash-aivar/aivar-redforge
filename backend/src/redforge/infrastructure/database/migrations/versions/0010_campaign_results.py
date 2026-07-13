"""Campaign results persistence — Sprint 42/43.

Adds:
  - campaign_results: stores the outcome of each red team campaign run.
    Written once after campaign completion, read-only thereafter.
    Scoped by organization_id for multi-tenant isolation.

Columns:
  - id: UUID primary key (campaign_id / graph_id)
  - organization_id: tenant scope (FK not enforced at DB level — domain enforces)
  - target_id: the AITarget that was attacked
  - state: terminal state of the campaign (COMPLETED / FAILED / CANCELLED / etc.)
  - goal_achieved: boolean
  - objective_name: human-readable goal name
  - total_nodes / nodes_executed / completed_nodes / failed_nodes / blocked_nodes
  - intelligence_confidence: float score
  - duration_ms: wall-clock milliseconds
  - failure_reason: nullable text
  - graph_snapshot: JSONB — serialized AttackGraph for node/edge detail view
  - created_at: when the campaign completed

Revision ID: 0010
"""

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: str = "0009"
branch_labels: None = None
depends_on: None = None


def upgrade() -> None:
    op.create_table(
        "campaign_results",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(36), nullable=False, index=True),
        sa.Column("target_id", sa.String(36), nullable=False),
        sa.Column("state", sa.String(50), nullable=False),
        sa.Column("goal_achieved", sa.Boolean, nullable=False, default=False),
        sa.Column("objective_name", sa.String(200), nullable=False, default=""),
        sa.Column("total_nodes", sa.Integer, nullable=False, default=0),
        sa.Column("nodes_executed", sa.Integer, nullable=False, default=0),
        sa.Column("completed_nodes", sa.Integer, nullable=False, default=0),
        sa.Column("failed_nodes", sa.Integer, nullable=False, default=0),
        sa.Column("blocked_nodes", sa.Integer, nullable=False, default=0),
        sa.Column("injected_nodes", sa.Integer, nullable=False, default=0),
        sa.Column("intelligence_confidence", sa.Float, nullable=False, default=0.0),
        sa.Column("duration_ms", sa.Integer, nullable=False, default=0),
        sa.Column("failure_reason", sa.Text, nullable=True),
        sa.Column("graph_snapshot", sa.JSON, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "ix_campaign_results_org_created",
        "campaign_results",
        ["organization_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_campaign_results_org_created", table_name="campaign_results")
    op.drop_table("campaign_results")
