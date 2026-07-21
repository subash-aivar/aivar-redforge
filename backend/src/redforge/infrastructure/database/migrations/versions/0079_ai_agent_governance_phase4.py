
"""0079 — M31 Phase 4 ai_agent_governance.

Creates ai_agent_governance schema with versioned agent operational envelopes,
deviation events, and action idempotency keys.

Migration chain: 0078 → 0079.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0079"
down_revision: str = "0078"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS ai_agent_governance")

    op.create_table(
        "agent_operational_envelopes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("ai_system_asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("state", sa.String(64), nullable=False),
        sa.Column("envelope_version", sa.Integer(), nullable=False),
        sa.Column("is_current", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("actions_json", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column(
            "resource_scopes_json", postgresql.JSONB(), nullable=False, server_default="[]"
        ),
        sa.Column("max_data_sensitivity", sa.String(64), nullable=False),
        sa.Column(
            "rate_ceilings_json", postgresql.JSONB(), nullable=False, server_default="[]"
        ),
        sa.Column(
            "requires_human_approval_json",
            postgresql.JSONB(),
            nullable=False,
            server_default="[]",
        ),
        sa.Column("approved_by_json", postgresql.JSONB(), nullable=True),
        sa.Column("effective_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("effective_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "tenant_id",
            "ai_system_asset_id",
            "envelope_version",
            name="uq_envelope_tenant_asset_version",
        ),
        schema="ai_agent_governance",
    )

    op.create_table(
        "agent_deviation_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("envelope_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("envelope_version", sa.Integer(), nullable=False),
        sa.Column("ai_system_asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("deviation_type", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(64), nullable=False),
        sa.Column("observed_action_json", postgresql.JSONB(), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("review_state", sa.String(64), nullable=False),
        sa.Column("review_notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("linked_revision_event_id", sa.String(128), nullable=True),
        sa.Column("idempotency_key", sa.String(256), nullable=False),
        schema="ai_agent_governance",
    )
    op.create_index(
        "ix_agent_deviation_events_tenant_detected",
        "agent_deviation_events",
        ["tenant_id", "detected_at"],
        unique=False,
        schema="ai_agent_governance",
    )

    op.create_table(
        "agent_action_idempotency",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("idempotency_key", sa.String(256), nullable=False),
        sa.Column("result", sa.String(64), nullable=False),
        sa.UniqueConstraint(
            "tenant_id", "idempotency_key", name="uq_agent_action_idempotency"
        ),
        schema="ai_agent_governance",
    )


def downgrade() -> None:
    op.drop_table("agent_action_idempotency", schema="ai_agent_governance")
    op.drop_index(
        "ix_agent_deviation_events_tenant_detected",
        table_name="agent_deviation_events",
        schema="ai_agent_governance",
    )
    op.drop_table("agent_deviation_events", schema="ai_agent_governance")
    op.drop_table("agent_operational_envelopes", schema="ai_agent_governance")
    op.execute("DROP SCHEMA IF EXISTS ai_agent_governance CASCADE")
