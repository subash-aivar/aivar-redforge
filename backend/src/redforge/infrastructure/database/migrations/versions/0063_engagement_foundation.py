"""0063 — M29 Phase 1 engagement governance foundation.

Creates schema ``engagement`` with:
- engagements (aggregate root)
- engagement_phases, engagement_approvals, engagement_participants
- rules_of_engagement, target_scope_entries
- target_authorizations
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0063"
down_revision: str = "0062"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_SCHEMA = "engagement"


def upgrade() -> None:
    op.execute(sa.text(f"CREATE SCHEMA IF NOT EXISTS {_SCHEMA}"))

    op.create_table(
        "engagements",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=512), nullable=False),
        sa.Column("classification", sa.String(length=64), nullable=False),
        sa.Column("owner_id", sa.String(length=256), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("kill_switch_state", sa.String(length=32), nullable=False),
        sa.Column("engagement_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("scope_hash", sa.String(length=64), nullable=True),
        sa.Column("approval_policy_json", postgresql.JSONB(), nullable=False),
        sa.Column("window_json", postgresql.JSONB(), nullable=True),
        sa.Column("objectives_json", postgresql.JSONB(), nullable=True),
        sa.Column("pending_scope_expansion_json", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_engagements_tenant_id",
        "engagements",
        ["tenant_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_engagements_tenant_state",
        "engagements",
        ["tenant_id", "state"],
        schema=_SCHEMA,
    )

    op.create_table(
        "engagement_phases",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "engagement_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(f"{_SCHEMA}.engagements.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("sort_order", sa.Integer(), nullable=False, server_default="0"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_engagement_phases_engagement_id",
        "engagement_phases",
        ["engagement_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_engagement_phases_tenant_id",
        "engagement_phases",
        ["tenant_id"],
        schema=_SCHEMA,
    )

    op.create_table(
        "engagement_approvals",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "engagement_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(f"{_SCHEMA}.engagements.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("approver_id", sa.String(length=256), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("approval_scope", sa.String(length=128), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(length=256), nullable=True),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_engagement_approvals_engagement_id",
        "engagement_approvals",
        ["engagement_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_engagement_approvals_tenant_id",
        "engagement_approvals",
        ["tenant_id"],
        schema=_SCHEMA,
    )

    op.create_table(
        "engagement_participants",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "engagement_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(f"{_SCHEMA}.engagements.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("operator_id", sa.String(length=256), nullable=False),
        sa.Column("role", sa.String(length=128), nullable=False),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint(
            "engagement_id",
            "operator_id",
            "added_at",
            name="uq_engagement_participants_op_added",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_engagement_participants_engagement_id",
        "engagement_participants",
        ["engagement_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_engagement_participants_tenant_id",
        "engagement_participants",
        ["tenant_id"],
        schema=_SCHEMA,
    )

    op.create_table(
        "rules_of_engagement",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "engagement_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(f"{_SCHEMA}.engagements.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("constraints_json", postgresql.JSONB(), nullable=False),
        sa.Column("signed_by", sa.String(length=256), nullable=True),
        sa.Column("signature", sa.Text(), nullable=True),
        sa.Column("signed_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint(
            "engagement_id",
            "version",
            name="uq_rules_of_engagement_version",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_rules_of_engagement_engagement_id",
        "rules_of_engagement",
        ["engagement_id"],
        schema=_SCHEMA,
    )

    op.create_table(
        "target_scope_entries",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "engagement_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(f"{_SCHEMA}.engagements.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("display_name", sa.String(length=512), nullable=True),
        sa.UniqueConstraint(
            "engagement_id",
            "asset_id",
            name="uq_target_scope_engagement_asset",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_target_scope_entries_engagement_id",
        "target_scope_entries",
        ["engagement_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_target_scope_entries_tenant_asset",
        "target_scope_entries",
        ["tenant_id", "asset_id"],
        schema=_SCHEMA,
    )

    op.create_table(
        "target_authorizations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("display_name", sa.String(length=512), nullable=True),
        sa.Column("techniques_json", postgresql.JSONB(), nullable=False),
        sa.Column("constraints_json", postgresql.JSONB(), nullable=False),
        sa.Column("granted_by", sa.String(length=256), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("phase_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "destruct_approval_granted",
            sa.Boolean(),
            nullable=False,
            server_default="false",
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_target_authorizations_tenant_id",
        "target_authorizations",
        ["tenant_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_target_authorizations_engagement",
        "target_authorizations",
        ["tenant_id", "engagement_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_target_authorizations_asset",
        "target_authorizations",
        ["tenant_id", "asset_id"],
        schema=_SCHEMA,
    )


def downgrade() -> None:
    op.drop_table("target_authorizations", schema=_SCHEMA)
    op.drop_table("target_scope_entries", schema=_SCHEMA)
    op.drop_table("rules_of_engagement", schema=_SCHEMA)
    op.drop_table("engagement_participants", schema=_SCHEMA)
    op.drop_table("engagement_approvals", schema=_SCHEMA)
    op.drop_table("engagement_phases", schema=_SCHEMA)
    op.drop_table("engagements", schema=_SCHEMA)
    op.execute(sa.text(f"DROP SCHEMA IF EXISTS {_SCHEMA}"))
