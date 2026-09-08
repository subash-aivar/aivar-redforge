"""0164 — campaign_intel foundation tables.

Migration chain: 0163 -> 0164.

Creates persistence for the `Campaign` aggregate root (a threat-intel
record of a REAL-WORLD adversary campaign — unrelated to RedForge's own
red-team campaign orchestration in `src/campaign`) plus its seven owned
child collections. New tables only — no changes to any existing table.

- campaign_intel_campaigns (`tenant_id` NULLABLE — `NULL` is a genuine
  global RedForge-curated record, never a reserved sentinel). Canonical
  identity is `canonical_name` (strongly normalized in the domain),
  scoped by ownership via two PARTIAL unique indexes — the same
  NULL-is-distinct-from-NULL-aware split migration 0163 already
  established for `malware_intel_malware`:
    - uq_campaign_intel_global_identity: unique on (canonical_name)
      WHERE tenant_id IS NULL
    - uq_campaign_intel_tenant_identity: unique on
      (tenant_id, canonical_name) WHERE tenant_id IS NOT NULL
  `status` (the real-world campaign's own operational state) and
  `lifecycle_status` (RedForge's own record lifecycle) are two separate,
  independently-indexed columns by design — they are orthogonal axes and
  collapsing them would erase a domain guarantee.
- campaign_intel_aliases (child, cascade delete)
- campaign_intel_objectives (child, cascade delete)
- campaign_intel_regions (child, cascade delete, unique per campaign)
- campaign_intel_target_sectors (child, cascade delete, unique per
  campaign)
- campaign_intel_evidence_citations (child, cascade delete)
- campaign_intel_source_attributions (child, cascade delete)
- campaign_intel_version_history (child, cascade delete, append-only —
  dedup key: campaign_id + version, unique per campaign)

No relationship table: cross-entity relationships involving campaigns
are owned exclusively by the `intelligence_relationships` bounded
context (migration 0162), whose `CAMPAIGN` entity type references a
`Campaign` by opaque `entity_id`.

No legacy data migration, no dual-write.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0164"
down_revision: str = "0163"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "campaign_intel_campaigns",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("canonical_name", sa.String(300), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("lifecycle_status", sa.String(16), nullable=False),
        sa.Column("motivation", sa.String(16), nullable=False),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("timeline_first_observed", sa.DateTime(timezone=True), nullable=True),
        sa.Column("timeline_last_observed", sa.DateTime(timezone=True), nullable=True),
        sa.Column("timeline_ongoing", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("superseded_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
    )
    op.create_index("ix_campaign_intel_campaigns_tenant", "campaign_intel_campaigns", ["tenant_id"])
    op.create_index(
        "ix_campaign_intel_campaigns_canonical_name",
        "campaign_intel_campaigns",
        ["canonical_name"],
    )
    op.create_index(
        "ix_campaign_intel_campaigns_lifecycle", "campaign_intel_campaigns", ["lifecycle_status"]
    )
    op.create_index("ix_campaign_intel_campaigns_status", "campaign_intel_campaigns", ["status"])
    op.create_index(
        "ix_campaign_intel_campaigns_motivation", "campaign_intel_campaigns", ["motivation"]
    )
    op.create_index(
        "uq_campaign_intel_global_identity",
        "campaign_intel_campaigns",
        ["canonical_name"],
        unique=True,
        postgresql_where=sa.text("tenant_id IS NULL"),
    )
    op.create_index(
        "uq_campaign_intel_tenant_identity",
        "campaign_intel_campaigns",
        ["tenant_id", "canonical_name"],
        unique=True,
        postgresql_where=sa.text("tenant_id IS NOT NULL"),
    )

    op.create_table(
        "campaign_intel_aliases",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "campaign_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("campaign_intel_campaigns.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("value", sa.String(300), nullable=False),
    )
    op.create_index("ix_campaign_intel_aliases_campaign", "campaign_intel_aliases", ["campaign_id"])

    op.create_table(
        "campaign_intel_objectives",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "campaign_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("campaign_intel_campaigns.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("objective_type", sa.String(32), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index(
        "ix_campaign_intel_objectives_campaign", "campaign_intel_objectives", ["campaign_id"]
    )

    op.create_table(
        "campaign_intel_regions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "campaign_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("campaign_intel_campaigns.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("region", sa.String(32), nullable=False),
    )
    op.create_index("ix_campaign_intel_regions_campaign", "campaign_intel_regions", ["campaign_id"])
    op.create_index(
        "uq_campaign_intel_regions_dedup",
        "campaign_intel_regions",
        ["campaign_id", "region"],
        unique=True,
    )

    op.create_table(
        "campaign_intel_target_sectors",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "campaign_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("campaign_intel_campaigns.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("target_sector", sa.String(32), nullable=False),
    )
    op.create_index(
        "ix_campaign_intel_target_sectors_campaign",
        "campaign_intel_target_sectors",
        ["campaign_id"],
    )
    op.create_index(
        "uq_campaign_intel_target_sectors_dedup",
        "campaign_intel_target_sectors",
        ["campaign_id", "target_sector"],
        unique=True,
    )

    op.create_table(
        "campaign_intel_evidence_citations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "campaign_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("campaign_intel_campaigns.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("value", sa.Text(), nullable=False),
    )
    op.create_index(
        "ix_campaign_intel_evidence_citations_campaign",
        "campaign_intel_evidence_citations",
        ["campaign_id"],
    )

    op.create_table(
        "campaign_intel_source_attributions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "campaign_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("campaign_intel_campaigns.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source_system", sa.String(128), nullable=False),
        sa.Column("reference", sa.String(512), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index(
        "ix_campaign_intel_source_attributions_campaign",
        "campaign_intel_source_attributions",
        ["campaign_id"],
    )

    op.create_table(
        "campaign_intel_version_history",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "campaign_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("campaign_intel_campaigns.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("change_summary", sa.Text(), nullable=False),
        sa.Column("source", sa.String(128), nullable=False),
    )
    op.create_index(
        "ix_campaign_intel_version_history_campaign",
        "campaign_intel_version_history",
        ["campaign_id"],
    )
    op.create_index(
        "uq_campaign_intel_version_history_dedup",
        "campaign_intel_version_history",
        ["campaign_id", "version"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_table("campaign_intel_version_history")
    op.drop_table("campaign_intel_source_attributions")
    op.drop_table("campaign_intel_evidence_citations")
    op.drop_table("campaign_intel_target_sectors")
    op.drop_table("campaign_intel_regions")
    op.drop_table("campaign_intel_objectives")
    op.drop_table("campaign_intel_aliases")
    op.drop_table("campaign_intel_campaigns")
