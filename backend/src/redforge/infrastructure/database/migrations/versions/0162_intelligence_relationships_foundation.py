"""0162 — intelligence_relationships foundation tables (M51.4 Phase C1).

Migration chain: 0161 -> 0162.

Creates persistence for the `IntelligenceRelationship` aggregate root
plus its three owned child collections. New tables only — no changes
to `ioc_intelligence_iocs`, `threat_actor_intel_threat_actors`,
`attack_pattern_intel_patterns`, or any MITRE reference-data table.
Relationship endpoints reference those contexts only by opaque
`*_entity_type`/`*_entity_id` string columns — NO foreign key crosses
a bounded-context boundary; endpoint existence is checked exclusively
at the application layer through read-only ACL ports.

- intelligence_relationships (`tenant_id` NULLABLE — `NULL` is a
  genuine global RedForge-curated record, never a reserved sentinel).
  Canonical identity is
  `(relationship_type, source_entity_type, source_entity_id,
    target_entity_type, target_entity_id)`, scoped by ownership via
  two PARTIAL unique indexes — the same
  NULL-is-distinct-from-NULL-aware split migrations 0160/0161 already
  established:
    - uq_intelligence_relationships_global_identity: unique on the
      five identity columns WHERE tenant_id IS NULL
    - uq_intelligence_relationships_tenant_identity: unique on
      (tenant_id + the five identity columns) WHERE tenant_id IS NOT
      NULL
- intelligence_relationship_evidence_citations (child, cascade delete)
- intelligence_relationship_source_attributions (child, cascade delete)
- intelligence_relationship_version_history (child, cascade delete,
  append-only — dedup key: relationship_id + version, unique per
  relationship)

No legacy data migration, no dual-write.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0162"
down_revision: str = "0161"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_IDENTITY_COLUMNS = [
    "relationship_type",
    "source_entity_type",
    "source_entity_id",
    "target_entity_type",
    "target_entity_id",
]


def upgrade() -> None:
    op.create_table(
        "intelligence_relationships",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("relationship_type", sa.String(64), nullable=False),
        sa.Column("source_entity_type", sa.String(32), nullable=False),
        sa.Column("source_entity_id", sa.String(512), nullable=False),
        sa.Column("target_entity_type", sa.String(32), nullable=False),
        sa.Column("target_entity_id", sa.String(512), nullable=False),
        sa.Column("direction", sa.String(16), nullable=False),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("epistemic_state", sa.String(16), nullable=False),
        sa.Column("lifecycle_status", sa.String(16), nullable=False),
        sa.Column("superseded_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
    )
    op.create_index(
        "ix_intelligence_relationships_tenant", "intelligence_relationships", ["tenant_id"]
    )
    op.create_index(
        "ix_intelligence_relationships_type",
        "intelligence_relationships",
        ["relationship_type"],
    )
    op.create_index(
        "ix_intelligence_relationships_lifecycle",
        "intelligence_relationships",
        ["lifecycle_status"],
    )
    op.create_index(
        "ix_intelligence_relationships_epistemic",
        "intelligence_relationships",
        ["epistemic_state"],
    )
    op.create_index(
        "ix_intelligence_relationships_source_entity",
        "intelligence_relationships",
        ["source_entity_id"],
    )
    op.create_index(
        "ix_intelligence_relationships_target_entity",
        "intelligence_relationships",
        ["target_entity_id"],
    )
    op.create_index(
        "uq_intelligence_relationships_global_identity",
        "intelligence_relationships",
        _IDENTITY_COLUMNS,
        unique=True,
        postgresql_where=sa.text("tenant_id IS NULL"),
    )
    op.create_index(
        "uq_intelligence_relationships_tenant_identity",
        "intelligence_relationships",
        ["tenant_id", *_IDENTITY_COLUMNS],
        unique=True,
        postgresql_where=sa.text("tenant_id IS NOT NULL"),
    )

    op.create_table(
        "intelligence_relationship_evidence_citations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "relationship_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("intelligence_relationships.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_index(
        "ix_intelligence_relationship_evidence_citations_parent",
        "intelligence_relationship_evidence_citations",
        ["relationship_id"],
    )

    op.create_table(
        "intelligence_relationship_source_attributions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "relationship_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("intelligence_relationships.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source_system", sa.String(128), nullable=False),
        sa.Column("reference", sa.String(512), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("position", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_index(
        "ix_intelligence_relationship_source_attributions_parent",
        "intelligence_relationship_source_attributions",
        ["relationship_id"],
    )

    op.create_table(
        "intelligence_relationship_version_history",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "relationship_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("intelligence_relationships.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("change_summary", sa.Text(), nullable=False),
        sa.Column("source", sa.String(128), nullable=False),
    )
    op.create_index(
        "ix_intelligence_relationship_version_history_parent",
        "intelligence_relationship_version_history",
        ["relationship_id"],
    )
    op.create_index(
        "uq_intelligence_relationship_version_history_dedup",
        "intelligence_relationship_version_history",
        ["relationship_id", "version"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_table("intelligence_relationship_version_history")
    op.drop_table("intelligence_relationship_source_attributions")
    op.drop_table("intelligence_relationship_evidence_citations")
    op.drop_table("intelligence_relationships")
