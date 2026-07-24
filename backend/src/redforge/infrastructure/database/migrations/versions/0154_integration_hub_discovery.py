"""0154 — Phase 2B migration.

Migration chain: 0153 → 0154.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0154"
down_revision: str = "0153"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.create_table(
        "discovered_assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("connector_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("vendor", sa.String(30), nullable=False),
        sa.Column("external_id", sa.Text(), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("category", sa.String(30), nullable=False),
        sa.Column("region", sa.Text(), nullable=True),
        sa.Column("owner", sa.Text(), nullable=True),
        sa.Column("security_state", sa.String(20), nullable=False, server_default="UNKNOWN"),
        sa.Column("compliance_state", sa.String(20), nullable=False, server_default="UNKNOWN"),
        sa.Column("health_status", sa.String(30), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("tags", postgresql.JSONB(), nullable=True),
        sa.Column("metadata", postgresql.JSONB(), nullable=True),
        sa.Column("configuration", postgresql.JSONB(), nullable=True),
        sa.Column("config_hash", sa.String(64), nullable=False),
        sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        schema="integration_hub",
    )
    op.create_index(
        "ix_discovered_assets_tenant_connector",
        "discovered_assets",
        ["tenant_id", "connector_id"],
        schema="integration_hub",
    )
    op.create_index(
        "ix_discovered_assets_tenant_vendor",
        "discovered_assets",
        ["tenant_id", "vendor"],
        schema="integration_hub",
    )
    op.create_index(
        "ix_discovered_assets_tenant_category",
        "discovered_assets",
        ["tenant_id", "category"],
        schema="integration_hub",
    )
    op.create_index(
        "ux_discovered_assets_tenant_fingerprint",
        "discovered_assets",
        ["tenant_id", "fingerprint"],
        unique=True,
        schema="integration_hub",
    )

    op.create_table(
        "asset_relationships",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "source_asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(
                "integration_hub.discovered_assets.id",
                name="fk_asset_relationships_source_asset",
                ondelete="CASCADE",
            ),
            nullable=False,
        ),
        sa.Column("target_asset_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("target_external_id", sa.Text(), nullable=False),
        sa.Column("relationship_type", sa.String(30), nullable=False),
        sa.Column("metadata", postgresql.JSONB(), nullable=True),
        schema="integration_hub",
    )
    op.create_index(
        "ix_asset_relationships_source",
        "asset_relationships",
        ["source_asset_id"],
        schema="integration_hub",
    )
    op.create_index(
        "ix_asset_relationships_tenant",
        "asset_relationships",
        ["tenant_id"],
        schema="integration_hub",
    )

    op.create_table(
        "sync_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("connector_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("mode", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("items_discovered", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("items_created", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("items_updated", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("items_deleted", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("cancelled", sa.Boolean(), nullable=False, server_default="false"),
        schema="integration_hub",
    )
    op.create_index(
        "ix_sync_runs_tenant_connector_started",
        "sync_runs",
        ["tenant_id", "connector_id", "started_at"],
        schema="integration_hub",
    )


def downgrade() -> None:

    op.drop_index(
        "ix_sync_runs_tenant_connector_started", table_name="sync_runs", schema="integration_hub"
    )
    op.drop_table("sync_runs", schema="integration_hub")

    op.drop_index(
        "ix_asset_relationships_tenant", table_name="asset_relationships", schema="integration_hub"
    )
    op.drop_index(
        "ix_asset_relationships_source", table_name="asset_relationships", schema="integration_hub"
    )
    op.drop_table("asset_relationships", schema="integration_hub")

    op.drop_index(
        "ux_discovered_assets_tenant_fingerprint",
        table_name="discovered_assets",
        schema="integration_hub",
    )
    op.drop_index(
        "ix_discovered_assets_tenant_category",
        table_name="discovered_assets",
        schema="integration_hub",
    )
    op.drop_index(
        "ix_discovered_assets_tenant_vendor",
        table_name="discovered_assets",
        schema="integration_hub",
    )
    op.drop_index(
        "ix_discovered_assets_tenant_connector",
        table_name="discovered_assets",
        schema="integration_hub",
    )
    op.drop_table("discovered_assets", schema="integration_hub")
