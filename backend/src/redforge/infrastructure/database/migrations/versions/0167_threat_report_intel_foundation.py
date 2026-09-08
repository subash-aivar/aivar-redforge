"""0167 — threat_report_intel foundation tables.

Migration chain: 0166 -> 0167.

Creates persistence for the `ThreatReport` aggregate root (a RedForge
record OF A PUBLISHED THREAT-INTELLIGENCE REPORT — who published it,
when, under what TLP marking, how severe the described threat is) plus
its four owned child collections. New tables only — no changes to any
existing table.

Deliberately NOT the same thing as a RedForge-generated report:
`reporting`, `analytics` and `regulatory_notification` keep ownership of
RedForge's OWN report/notification artefacts. Those tables are neither
touched nor referenced.

- threat_report_intel_reports (`tenant_id` NULLABLE — `NULL` is a
  genuine global RedForge-curated record, never a reserved sentinel).
  Canonical identity is `canonical_title` (strongly normalized in the
  domain), scoped by ownership via two PARTIAL unique indexes — the same
  NULL-is-distinct-from-NULL-aware split migration 0166 already
  established for `infrastructure_intel_infrastructure`:
    - uq_threat_report_intel_global_identity: unique on
      (canonical_title) WHERE tenant_id IS NULL
    - uq_threat_report_intel_tenant_identity: unique on
      (tenant_id, canonical_title) WHERE tenant_id IS NOT NULL
  `title` (the analyst's real display value) is stored as a SEPARATE,
  non-normalized, non-unique column alongside `canonical_title`.
  `executive_summary` and `technical_summary` are two DISTINCT NOT NULL
  text columns — leadership-level and analyst-level respectively, never
  conflated.
- threat_report_intel_references (child, cascade delete)
- threat_report_intel_evidence_citations (child, cascade delete)
- threat_report_intel_source_attributions (child, cascade delete)
- threat_report_intel_version_history (child, cascade delete,
  append-only — dedup key: threat_report_id + version)

No relationship table: cross-entity relationships involving a threat
report are owned exclusively by the `intelligence_relationships`
bounded context (migration 0162), which already defines `THREAT_REPORT`
in its closed `EntityType` enum and (as of M51.9 Phase H1, migration
0162's later evolution) defines `THREAT_REPORT_TO_*` `RelationshipType`
values, so report-to-anything links are expressible today via that
context. The `id` column here is exactly the opaque `entity_id` those
relationship types carry. Not duplicating that table here is a
deliberate design choice, not a gap — see the `ThreatReport` aggregate's
module docstring.

No legacy data migration, no dual-write.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0167"
down_revision: str = "0166"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "threat_report_intel_reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("canonical_title", sa.String(512), nullable=False),
        sa.Column("publisher_organization_name", sa.String(300), nullable=False),
        sa.Column("publisher_contact", sa.String(300), nullable=False, server_default=""),
        sa.Column("publication_date", sa.Date(), nullable=False),
        sa.Column("report_type", sa.String(64), nullable=False),
        sa.Column("tlp_marking", sa.String(32), nullable=False),
        sa.Column("external_report_id", sa.String(256), nullable=False, server_default=""),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("executive_summary", sa.Text(), nullable=False),
        sa.Column("technical_summary", sa.Text(), nullable=False),
        sa.Column("lifecycle_status", sa.String(16), nullable=False),
        sa.Column("superseded_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
    )
    op.create_index(
        "ix_threat_report_intel_tenant",
        "threat_report_intel_reports",
        ["tenant_id"],
    )
    op.create_index(
        "ix_threat_report_intel_canonical_title",
        "threat_report_intel_reports",
        ["canonical_title"],
    )
    op.create_index(
        "ix_threat_report_intel_lifecycle",
        "threat_report_intel_reports",
        ["lifecycle_status"],
    )
    op.create_index(
        "ix_threat_report_intel_severity",
        "threat_report_intel_reports",
        ["severity"],
    )
    op.create_index(
        "ix_threat_report_intel_tlp",
        "threat_report_intel_reports",
        ["tlp_marking"],
    )
    op.create_index(
        "ix_threat_report_intel_publication_date",
        "threat_report_intel_reports",
        ["publication_date"],
    )
    op.create_index(
        "uq_threat_report_intel_global_identity",
        "threat_report_intel_reports",
        ["canonical_title"],
        unique=True,
        postgresql_where=sa.text("tenant_id IS NULL"),
    )
    op.create_index(
        "uq_threat_report_intel_tenant_identity",
        "threat_report_intel_reports",
        ["tenant_id", "canonical_title"],
        unique=True,
        postgresql_where=sa.text("tenant_id IS NOT NULL"),
    )

    op.create_table(
        "threat_report_intel_references",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "threat_report_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("threat_report_intel_reports.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("url_or_citation", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index(
        "ix_threat_report_intel_references_parent",
        "threat_report_intel_references",
        ["threat_report_id"],
    )

    op.create_table(
        "threat_report_intel_evidence_citations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "threat_report_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("threat_report_intel_reports.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("value", sa.Text(), nullable=False),
    )
    op.create_index(
        "ix_threat_report_intel_evidence_citations_parent",
        "threat_report_intel_evidence_citations",
        ["threat_report_id"],
    )

    op.create_table(
        "threat_report_intel_source_attributions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "threat_report_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("threat_report_intel_reports.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source_system", sa.String(128), nullable=False),
        sa.Column("reference", sa.String(512), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index(
        "ix_threat_report_intel_source_attributions_parent",
        "threat_report_intel_source_attributions",
        ["threat_report_id"],
    )

    op.create_table(
        "threat_report_intel_version_history",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "threat_report_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("threat_report_intel_reports.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("change_summary", sa.Text(), nullable=False),
        sa.Column("source", sa.String(128), nullable=False),
    )
    op.create_index(
        "ix_threat_report_intel_version_history_parent",
        "threat_report_intel_version_history",
        ["threat_report_id"],
    )
    op.create_index(
        "uq_threat_report_intel_version_history_dedup",
        "threat_report_intel_version_history",
        ["threat_report_id", "version"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_table("threat_report_intel_version_history")
    op.drop_table("threat_report_intel_source_attributions")
    op.drop_table("threat_report_intel_evidence_citations")
    op.drop_table("threat_report_intel_references")
    op.drop_table("threat_report_intel_reports")
