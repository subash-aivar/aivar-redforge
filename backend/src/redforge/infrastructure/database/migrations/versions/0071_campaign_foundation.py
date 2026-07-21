"""0071 — M30 Phase 1 campaign bounded context foundation.

Creates the campaign schema with tables for campaigns, campaign objectives,
campaign approvals, and campaign instances.

Migration chain: 0070 (M29 read models) → 0071 (campaign foundation).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0071"
down_revision: str = "0070"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_SCHEMA = "campaign"


def upgrade() -> None:
    op.execute(sa.text(f"CREATE SCHEMA IF NOT EXISTS {_SCHEMA}"))

    # campaigns — Campaign aggregate root
    op.create_table(
        "campaigns",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=512), nullable=False),
        sa.Column("classification", sa.String(length=64), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("owner_id", sa.String(length=256), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("engagement_tenant_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "safety_policy_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column(
            "approval_policy_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column(
            "schedule_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column(
            "target_selection_rules_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="[]",
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_campaign_campaigns_tenant",
        "campaigns",
        ["tenant_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_campaign_campaigns_tenant_state",
        "campaigns",
        ["tenant_id", "state"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_campaign_campaigns_engagement",
        "campaigns",
        ["engagement_id"],
        schema=_SCHEMA,
    )

    # campaign_objectives — CampaignObjective entities
    op.create_table(
        "campaign_objectives",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "campaign_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(f"{_SCHEMA}.campaigns.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("objective_type", sa.String(length=64), nullable=False),
        sa.Column("description", sa.String(length=1024), nullable=False),
        sa.Column(
            "evaluation_criteria_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column("state", sa.String(length=32), nullable=False, server_default="Pending"),
        sa.Column("sealed", sa.Boolean(), nullable=False, server_default="false"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_campaign_campaign_objectives_campaign",
        "campaign_objectives",
        ["campaign_id"],
        schema=_SCHEMA,
    )

    # campaign_approvals — CampaignApproval entities
    op.create_table(
        "campaign_approvals",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "campaign_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(f"{_SCHEMA}.campaigns.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("approver_id", sa.String(length=256), nullable=False),
        sa.Column("signature", sa.String(length=1024), nullable=False),
        sa.Column("approval_scope", sa.String(length=128), nullable=False, server_default="campaign"),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(length=256), nullable=True),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_campaign_campaign_approvals_campaign",
        "campaign_approvals",
        ["campaign_id"],
        schema=_SCHEMA,
    )

    # campaign_instances — CampaignInstance aggregate root
    op.create_table(
        "campaign_instances",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "campaign_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(f"{_SCHEMA}.campaigns.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("run_number", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column(
            "resolved_targets_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="[]",
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_campaign_campaign_instances_tenant",
        "campaign_instances",
        ["tenant_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_campaign_campaign_instances_campaign",
        "campaign_instances",
        ["campaign_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_campaign_campaign_instances_tenant_state",
        "campaign_instances",
        ["tenant_id", "state"],
        schema=_SCHEMA,
    )
    # Unique constraint: one run_number per campaign
    op.create_unique_constraint(
        "uq_campaign_instances_campaign_run_number",
        "campaign_instances",
        ["campaign_id", "run_number"],
        schema=_SCHEMA,
    )


def downgrade() -> None:
    op.drop_table("campaign_instances", schema=_SCHEMA)
    op.drop_table("campaign_approvals", schema=_SCHEMA)
    op.drop_table("campaign_objectives", schema=_SCHEMA)
    op.drop_table("campaigns", schema=_SCHEMA)
    op.execute(sa.text(f"DROP SCHEMA IF EXISTS {_SCHEMA}"))
