"""Unified asset & connector foundation — M3.

Adds:
  - ai_assets: canonical tenant-owned asset inventory. Reuses the EXISTING
    `AIAsset` domain aggregate (Sprint 22, domain/inventory/) — this is a
    persistence layer for an aggregate that already existed only
    in-memory. Rich nested value objects (fingerprint, version_history,
    relationships, dependencies, metadata) are stored as a JSON blob
    (`data`), matching the document-store precedent set by `providers`
    (Sprint 42-43); a small set of relational columns duplicate the
    fields needed for tenant-scoped uniqueness/query/indexing.
    Tenant-scoped identity uniqueness is a partial unique index on
    (organization_id, external_id) WHERE external_id != '' — assets with
    no external identity (manually registered, no dedup key) are exempt.
  - connectors: canonical tenant-owned connector configurations, same
    JSON-blob + relational-columns pattern, reusing the EXISTING
    `Connector` domain aggregate (Sprint 23, domain/connectors/).
    `discovery_history` (a tuple of DiscoveryJobRecord, already modeling
    exactly the PENDING/RUNNING/COMPLETED/FAILED/CANCELLED lifecycle M3
    calls "Discovery Run") lives inside the same JSON blob — no separate
    discovery_runs table, since the aggregate already owns this history
    and splitting it out would create two sources of truth for the same
    data.

Revision ID: 0013
"""

import sqlalchemy as sa
from alembic import op

revision: str = "0013"
down_revision: str = "0012"
branch_labels: None = None
depends_on: None = None


def upgrade() -> None:
    op.create_table(
        "ai_assets",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("asset_type", sa.String(50), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("external_id", sa.String(255), nullable=False, server_default=""),
        sa.Column("discovery_source", sa.String(50), nullable=False),
        sa.Column("lifecycle_stage", sa.String(30), nullable=False),
        sa.Column("data", sa.JSON, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_ai_assets_organization_id", "ai_assets", ["organization_id"])
    op.create_index(
        "ix_ai_assets_org_type", "ai_assets", ["organization_id", "asset_type"],
    )
    # Tenant-scoped identity uniqueness — the core M3 race-safety
    # invariant. Two concurrent discovery operations for the same
    # (organization_id, external_id) can insert concurrently; the second
    # commit hits this constraint and must be handled as an update-path,
    # not a duplicate (see AssetIdentityResolver).
    op.create_index(
        "ux_ai_assets_org_external_id",
        "ai_assets",
        ["organization_id", "external_id"],
        unique=True,
        postgresql_where=sa.text("external_id != ''"),
    )

    op.create_table(
        "connectors",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("connector_type", sa.String(50), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("data", sa.JSON, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_connectors_organization_id", "connectors", ["organization_id"])
    op.create_index(
        "ux_connectors_org_name", "connectors", ["organization_id", "name"], unique=True,
    )


def downgrade() -> None:
    op.drop_index("ux_connectors_org_name", table_name="connectors")
    op.drop_index("ix_connectors_organization_id", table_name="connectors")
    op.drop_table("connectors")

    op.drop_index("ux_ai_assets_org_external_id", table_name="ai_assets")
    op.drop_index("ix_ai_assets_org_type", table_name="ai_assets")
    op.drop_index("ix_ai_assets_organization_id", table_name="ai_assets")
    op.drop_table("ai_assets")
