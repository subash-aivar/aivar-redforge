"""Security Operations Command Center read models & integration seams — M18.

M18 is predominantly a read-model expansion over M1-M17 truth (posture
score, top-ports aggregation, behavior analytics, network-drift feed
wiring) and adds NO second source of authoritative domain state for any
of those. This migration therefore adds only three narrowly-scoped
schema objects:

  1. ix_no_org_obstype_outcome — a supporting composite index on
     network_observations(organization_id, observation_type, outcome).
     The top-open-ports aggregation is a per-org GROUP BY over
     tcp-reachability observations; this index lets Postgres restrict
     the scan to the relevant observation rows instead of every
     observation the org has ever recorded. No new truth.

  2. integration_providers — the provider-neutral integration BOUNDARY
     for the six external-telemetry capabilities that have no data
     source in the platform (firewall, network/bandwidth telemetry,
     connectivity/ISP, backup/DR, threat intelligence, geolocation).
     A row records only a provider DESCRIPTOR (type, name, status,
     an allowlisted non-secret config blob, last_telemetry_at). It is
     the seam a real provider integration would later populate; with
     zero rows (the default), every capability reports NOT_CONFIGURED
     and the platform NEVER fabricates telemetry. No secret is ever
     stored here (enforced in the application layer's allowlist).

  3. network_zone_assignments — explicit, admin-authored network-zone
     classification. Per the M18 brief, an asset is NEVER auto-labelled
     DMZ/INTERNET_EDGE from an RFC1918/public-IP heuristic; a zone is a
     deliberate organization-administration assignment. Composite FK to
     ai_assets(id, organization_id) makes a cross-tenant assignment a
     database-level impossibility (same pattern as M16/M17). An asset
     belongs to at most one zone (unique per (organization_id,
     asset_id)); absence of a row = UNKNOWN zone.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0028"
down_revision: str = "0027"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "ix_no_org_obstype_outcome",
        "network_observations",
        ["organization_id", "observation_type", "outcome"],
    )

    op.create_table(
        "integration_providers",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("integration_type", sa.String(30), nullable=False),
        sa.Column("provider_name", sa.String(100), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column("last_telemetry_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("registered_by", sa.String(26), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("id", "organization_id", name="ux_intp_id_org"),
        sa.UniqueConstraint(
            "organization_id", "integration_type", name="ux_intp_org_type",
        ),
    )
    op.create_index(
        "ix_intp_org_type", "integration_providers", ["organization_id", "integration_type"],
    )

    op.create_table(
        "network_zone_assignments",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("asset_id", sa.String(26), nullable=False),
        sa.Column("zone_type", sa.String(20), nullable=False),
        sa.Column("note", sa.String(500), nullable=False, server_default=""),
        sa.Column("assigned_by", sa.String(26), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("id", "organization_id", name="ux_nza_id_org"),
        sa.UniqueConstraint("organization_id", "asset_id", name="ux_nza_org_asset"),
        sa.ForeignKeyConstraint(
            ["asset_id", "organization_id"],
            ["ai_assets.id", "ai_assets.organization_id"],
            name="fk_nza_same_tenant_asset",
            ondelete="CASCADE",
        ),
    )
    op.create_index(
        "ix_nza_org_zone", "network_zone_assignments", ["organization_id", "zone_type"],
    )


def downgrade() -> None:
    op.drop_index("ix_nza_org_zone", table_name="network_zone_assignments")
    op.drop_table("network_zone_assignments")
    op.drop_index("ix_intp_org_type", table_name="integration_providers")
    op.drop_table("integration_providers")
    op.drop_index("ix_no_org_obstype_outcome", table_name="network_observations")
