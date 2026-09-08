"""0166 — infrastructure_intel foundation tables.

Migration chain: 0165 -> 0166.

Creates persistence for the `Infrastructure` aggregate root (a
threat-intel record of the HOSTING / OWNERSHIP FOOTPRINT ENTITY behind
adversary infrastructure — an ASN, a hosting provider, a cloud tenancy,
or a domain/IP/URL considered AS INFRASTRUCTURE) plus its four owned
child collections. New tables only — no changes to any existing table.

Deliberately NOT the same thing as an atomic indicator observation:
`ioc_intelligence` (migration-wise untouched here) keeps ownership of
IP/DOMAIN/URL/HASH `IndicatorType` sightings. A specific IP tracked as
an IOC is linked to an Infrastructure row externally through
`intelligence_relationships`' `IOC_TO_INFRASTRUCTURE` type, never
merged into these tables.

Equally unrelated to `attack_surface_management` (RedForge's OWN
discovered attack surface), `cloud_security` (RedForge's OWN cloud
account registrations) and the AI asset inventory — none of those
tables are touched or referenced.

- infrastructure_intel_infrastructure (`tenant_id` NULLABLE — `NULL` is
  a genuine global RedForge-curated record, never a reserved sentinel).
  Canonical identity is `(infrastructure_type, normalized_identifier)`
  (strongly normalized per type in the domain), scoped by ownership via
  two PARTIAL unique indexes — the same
  NULL-is-distinct-from-NULL-aware split migration 0165 already
  established for `tool_intel_tools`:
    - uq_infrastructure_intel_global_identity: unique on
      (infrastructure_type, normalized_identifier)
      WHERE tenant_id IS NULL
    - uq_infrastructure_intel_tenant_identity: unique on
      (tenant_id, infrastructure_type, normalized_identifier)
      WHERE tenant_id IS NOT NULL
  Single-valued facets live as nullable columns: hosting_provider_name,
  cloud_provider, and the network-ownership triple
  (registrant_organization / abuse_contact / ownership_notes).
- infrastructure_intel_regions (child, cascade delete, unique per row)
- infrastructure_intel_evidence_citations (child, cascade delete)
- infrastructure_intel_source_attributions (child, cascade delete)
- infrastructure_intel_version_history (child, cascade delete,
  append-only — dedup key: infrastructure_id + version)

No relationship table: cross-entity relationships involving adversary
infrastructure are owned exclusively by the
`intelligence_relationships` bounded context (migration 0162), whose
`INFRASTRUCTURE` entity type references an `Infrastructure` by opaque
`entity_id` (see `IOC_TO_INFRASTRUCTURE` and
`INFRASTRUCTURE_TO_CAMPAIGN`).

No legacy data migration, no dual-write.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0166"
down_revision: str = "0165"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "infrastructure_intel_infrastructure",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("infrastructure_type", sa.String(32), nullable=False),
        sa.Column("normalized_identifier", sa.String(512), nullable=False),
        sa.Column("lifecycle_status", sa.String(16), nullable=False),
        sa.Column("hosting_provider_name", sa.String(300), nullable=True),
        sa.Column("cloud_provider", sa.String(32), nullable=True),
        sa.Column("registrant_organization", sa.String(300), nullable=True),
        sa.Column("abuse_contact", sa.String(300), nullable=False, server_default=""),
        sa.Column("ownership_notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("superseded_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
    )
    op.create_index(
        "ix_infrastructure_intel_tenant",
        "infrastructure_intel_infrastructure",
        ["tenant_id"],
    )
    op.create_index(
        "ix_infrastructure_intel_identifier",
        "infrastructure_intel_infrastructure",
        ["normalized_identifier"],
    )
    op.create_index(
        "ix_infrastructure_intel_lifecycle",
        "infrastructure_intel_infrastructure",
        ["lifecycle_status"],
    )
    op.create_index(
        "ix_infrastructure_intel_type",
        "infrastructure_intel_infrastructure",
        ["infrastructure_type"],
    )
    op.create_index(
        "ix_infrastructure_intel_cloud_provider",
        "infrastructure_intel_infrastructure",
        ["cloud_provider"],
    )
    op.create_index(
        "uq_infrastructure_intel_global_identity",
        "infrastructure_intel_infrastructure",
        ["infrastructure_type", "normalized_identifier"],
        unique=True,
        postgresql_where=sa.text("tenant_id IS NULL"),
    )
    op.create_index(
        "uq_infrastructure_intel_tenant_identity",
        "infrastructure_intel_infrastructure",
        ["tenant_id", "infrastructure_type", "normalized_identifier"],
        unique=True,
        postgresql_where=sa.text("tenant_id IS NOT NULL"),
    )

    op.create_table(
        "infrastructure_intel_regions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "infrastructure_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("infrastructure_intel_infrastructure.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("region_code", sa.String(128), nullable=False),
    )
    op.create_index(
        "ix_infrastructure_intel_regions_parent",
        "infrastructure_intel_regions",
        ["infrastructure_id"],
    )
    op.create_index(
        "uq_infrastructure_intel_regions_dedup",
        "infrastructure_intel_regions",
        ["infrastructure_id", "region_code"],
        unique=True,
    )

    op.create_table(
        "infrastructure_intel_evidence_citations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "infrastructure_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("infrastructure_intel_infrastructure.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("value", sa.Text(), nullable=False),
    )
    op.create_index(
        "ix_infrastructure_intel_evidence_citations_parent",
        "infrastructure_intel_evidence_citations",
        ["infrastructure_id"],
    )

    op.create_table(
        "infrastructure_intel_source_attributions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "infrastructure_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("infrastructure_intel_infrastructure.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source_system", sa.String(128), nullable=False),
        sa.Column("reference", sa.String(512), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index(
        "ix_infrastructure_intel_source_attributions_parent",
        "infrastructure_intel_source_attributions",
        ["infrastructure_id"],
    )

    op.create_table(
        "infrastructure_intel_version_history",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "infrastructure_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("infrastructure_intel_infrastructure.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("change_summary", sa.Text(), nullable=False),
        sa.Column("source", sa.String(128), nullable=False),
    )
    op.create_index(
        "ix_infrastructure_intel_version_history_parent",
        "infrastructure_intel_version_history",
        ["infrastructure_id"],
    )
    op.create_index(
        "uq_infrastructure_intel_version_history_dedup",
        "infrastructure_intel_version_history",
        ["infrastructure_id", "version"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_table("infrastructure_intel_version_history")
    op.drop_table("infrastructure_intel_source_attributions")
    op.drop_table("infrastructure_intel_evidence_citations")
    op.drop_table("infrastructure_intel_regions")
    op.drop_table("infrastructure_intel_infrastructure")
