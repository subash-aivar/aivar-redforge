
"""0076 — M31 Phase 1 ai_posture foundation.

Creates ai_posture schema with:
- ai_system_assets
- shadow_ai_alerts
- ai_posture_tenant_settings (discovery-only mode)

Migration chain: 0075 → 0076.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0076"
down_revision: str = "0075"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS ai_posture")

    op.create_table(
        "ai_system_assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("asset_ref_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_ref_type", sa.String(64), nullable=False, server_default="AIAsset"),
        sa.Column("lifecycle_state", sa.String(64), nullable=False, index=True),
        sa.Column("registration_status", sa.String(64), nullable=False, index=True),
        sa.Column("ai_system_kind", sa.String(64), nullable=True),
        sa.Column("business_owner_id", sa.String(256), nullable=True),
        sa.Column("business_owner_name", sa.String(256), nullable=True),
        sa.Column("data_sensitivity", sa.String(64), nullable=False),
        sa.Column("discovery_source", sa.String(64), nullable=False),
        sa.Column("discovery_first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("discovery_last_confirmed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("threat_profile_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("risk_score_snapshot_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "tenant_id", "asset_ref_id", name="uq_ai_system_assets_tenant_asset_ref"
        ),
        schema="ai_posture",
    )

    op.create_table(
        "shadow_ai_alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("discovery_source", sa.String(64), nullable=False),
        sa.Column("cloud_account", sa.String(256), nullable=False),
        sa.Column("resource_identifier", sa.String(512), nullable=False),
        sa.Column("service_type", sa.String(256), nullable=False),
        sa.Column("region", sa.String(128), nullable=False),
        sa.Column("fingerprint_hash", sa.String(64), nullable=False),
        sa.Column("state", sa.String(64), nullable=False, index=True),
        sa.Column("triage_notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("resolution_action", sa.String(64), nullable=True),
        sa.Column("linked_asset_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("first_detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_confirmed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "tenant_id",
            "discovery_source",
            "fingerprint_hash",
            name="uq_shadow_ai_alerts_tenant_source_fp",
        ),
        schema="ai_posture",
    )

    op.create_table(
        "ai_posture_tenant_settings",
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "discovery_only_mode",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        schema="ai_posture",
    )


def downgrade() -> None:
    op.drop_table("ai_posture_tenant_settings", schema="ai_posture")
    op.drop_table("shadow_ai_alerts", schema="ai_posture")
    op.drop_table("ai_system_assets", schema="ai_posture")
    op.execute("DROP SCHEMA IF EXISTS ai_posture CASCADE")
