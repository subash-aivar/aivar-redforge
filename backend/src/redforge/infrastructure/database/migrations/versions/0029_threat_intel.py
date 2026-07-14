"""Threat Intelligence bounded context — M18 live-telemetry expansion pass.

Three tables, all genuinely new persistence (evidence-justified: caching/
TTL, admin config, and provider health all require durable state that
did not exist anywhere in M1-M18):

  1. threat_intel_providers — per-organization admin enable/disable +
     allowlisted config + credential REFERENCE (never a secret value),
     mirroring the exact pattern of M18's integration_providers table.
     Zero/disabled rows mean that provider is never called for that org.

  2. threat_intel_indicators — canonical (org, indicator_type, indicator)
     identity, created only when RedForge genuinely observes/queries it.

  3. threat_intel_enrichments — cached evidence per (indicator, provider,
     kind), doubling as the minimal provider-health signal via
     success/error_category. Composite FK to threat_intel_indicators
     makes cross-tenant enrichment a database-level impossibility, same
     pattern as M16/M18's asset/zone FKs.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0029"
down_revision: str = "0028"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "threat_intel_providers",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("provider_name", sa.String(40), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("allowed_indicator_types", sa.JSON(), nullable=False),
        sa.Column("credential_ref", sa.String(200), nullable=True),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column("updated_by", sa.String(26), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("id", "organization_id", name="ux_tip_id_org"),
        sa.UniqueConstraint("organization_id", "provider_name", name="ux_tip_org_provider"),
    )
    op.create_index(
        "ix_tip_org_provider", "threat_intel_providers", ["organization_id", "provider_name"]
    )

    op.create_table(
        "threat_intel_indicators",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("indicator", sa.String(512), nullable=False),
        sa.Column("indicator_type", sa.String(20), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("id", "organization_id", name="ux_tii_id_org"),
        sa.UniqueConstraint(
            "organization_id",
            "indicator_type",
            "indicator",
            name="ux_tii_org_type_indicator",
        ),
    )
    op.create_index(
        "ix_tii_org_last_seen", "threat_intel_indicators", ["organization_id", "last_seen_at"]
    )

    op.create_table(
        "threat_intel_enrichments",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("indicator_id", sa.String(26), nullable=False),
        sa.Column("provider_name", sa.String(40), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("error_category", sa.String(40), nullable=True),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("id", "organization_id", name="ux_tie_id_org"),
        sa.UniqueConstraint(
            "organization_id",
            "indicator_id",
            "provider_name",
            "kind",
            name="ux_tie_org_indicator_provider_kind",
        ),
        sa.ForeignKeyConstraint(
            ["indicator_id", "organization_id"],
            ["threat_intel_indicators.id", "threat_intel_indicators.organization_id"],
            name="fk_tie_same_tenant_indicator",
            ondelete="CASCADE",
        ),
    )
    op.create_index(
        "ix_tie_org_provider_fetched",
        "threat_intel_enrichments",
        ["organization_id", "provider_name", "fetched_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_tie_org_provider_fetched", table_name="threat_intel_enrichments")
    op.drop_table("threat_intel_enrichments")
    op.drop_index("ix_tii_org_last_seen", table_name="threat_intel_indicators")
    op.drop_table("threat_intel_indicators")
    op.drop_index("ix_tip_org_provider", table_name="threat_intel_providers")
    op.drop_table("threat_intel_providers")
