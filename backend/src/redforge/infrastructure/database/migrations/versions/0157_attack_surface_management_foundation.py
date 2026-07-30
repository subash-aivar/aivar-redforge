"""0157 — attack_surface_management foundation tables (M49C).

Migration chain: 0156 -> 0157.

Creates persistence for the two attack_surface_management aggregate
roots (`Asset`, `NetworkRange`) plus `Asset`'s child tables:

- attack_surface_assets / attack_surface_asset_ports /
  attack_surface_asset_certificates / attack_surface_asset_dns_records /
  attack_surface_asset_fingerprints
- attack_surface_network_ranges
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0157"
down_revision: str = "0156"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "attack_surface_assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_type", sa.String(32), nullable=False),
        sa.Column("domain_name", sa.String(253), nullable=True),
        sa.Column("subdomain_fqdn", sa.String(253), nullable=True),
        sa.Column("subdomain_parent", sa.String(253), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("discovery_source", sa.String(32), nullable=False),
        sa.Column("classification", sa.String(32), nullable=False),
        sa.Column("criticality", sa.String(32), nullable=False),
        sa.Column("exposure_state", sa.String(32), nullable=False),
        sa.Column("lifecycle_state", sa.String(32), nullable=False),
        sa.Column("ownership_owning_team", sa.String(256), nullable=True),
        sa.Column("ownership_contact", sa.String(256), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
    )
    op.create_index("ix_attack_surface_assets_tenant", "attack_surface_assets", ["tenant_id"])
    op.create_index(
        "ix_attack_surface_assets_tenant_type",
        "attack_surface_assets",
        ["tenant_id", "asset_type"],
    )
    op.create_index(
        "ix_attack_surface_assets_tenant_lifecycle",
        "attack_surface_assets",
        ["tenant_id", "lifecycle_state"],
    )

    op.create_table(
        "attack_surface_asset_ports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("attack_surface_assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("port_number", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(16), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("service_name", sa.String(128), nullable=True),
        sa.Column("service_version", sa.String(128), nullable=True),
        sa.Column("service_banner", sa.String(1024), nullable=True),
    )
    op.create_index(
        "ix_attack_surface_asset_ports_asset", "attack_surface_asset_ports", ["asset_id"]
    )

    op.create_table(
        "attack_surface_asset_certificates",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("attack_surface_assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("common_name", sa.String(512), nullable=False),
        sa.Column("issuer", sa.String(512), nullable=False),
        sa.Column("serial_number", sa.String(256), nullable=False),
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=False),
        sa.Column("not_after", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
    )
    op.create_index(
        "ix_attack_surface_asset_certificates_asset",
        "attack_surface_asset_certificates",
        ["asset_id"],
    )

    op.create_table(
        "attack_surface_asset_dns_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("attack_surface_assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("record_type", sa.String(16), nullable=False),
        sa.Column("name", sa.String(512), nullable=False),
        sa.Column("value", sa.String(1024), nullable=False),
        sa.Column("ttl_seconds", sa.Integer(), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_attack_surface_asset_dns_records_asset",
        "attack_surface_asset_dns_records",
        ["asset_id"],
    )

    op.create_table(
        "attack_surface_asset_fingerprints",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("attack_surface_assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("version", sa.String(128), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.UniqueConstraint(
            "asset_id", "ordinal", name="uq_attack_surface_asset_fingerprints_ordinal"
        ),
    )
    op.create_index(
        "ix_attack_surface_asset_fingerprints_asset",
        "attack_surface_asset_fingerprints",
        ["asset_id"],
    )

    op.create_table(
        "attack_surface_network_ranges",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("cidr", sa.String(64), nullable=False),
        sa.Column("discovery_source", sa.String(32), nullable=False),
        sa.Column("lifecycle_state", sa.String(32), nullable=False),
        sa.Column("asset_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
    )
    op.create_index(
        "ix_attack_surface_network_ranges_tenant",
        "attack_surface_network_ranges",
        ["tenant_id"],
    )
    op.create_index(
        "ix_attack_surface_network_ranges_tenant_lifecycle",
        "attack_surface_network_ranges",
        ["tenant_id", "lifecycle_state"],
    )


def downgrade() -> None:
    op.drop_table("attack_surface_network_ranges")
    op.drop_table("attack_surface_asset_fingerprints")
    op.drop_table("attack_surface_asset_dns_records")
    op.drop_table("attack_surface_asset_certificates")
    op.drop_table("attack_surface_asset_ports")
    op.drop_table("attack_surface_assets")
