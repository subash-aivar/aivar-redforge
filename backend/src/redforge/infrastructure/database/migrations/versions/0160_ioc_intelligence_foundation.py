"""0160 — ioc_intelligence foundation tables (M51.2 Phase A3).

Migration chain: 0159 -> 0160.

Creates persistence for the `IOC` aggregate root plus its two child
collections:

- ioc_intelligence_iocs (`tenant_id` NULLABLE — `NULL` is a genuine
  global reference record, never a reserved sentinel). Canonical
  identity is `(ioc_type, normalized_value)`, scoped by ownership via
  two PARTIAL unique indexes rather than one plain composite unique
  constraint: PostgreSQL treats every NULL as distinct from every
  other NULL in a unique-constraint comparison, so a plain
  `UNIQUE(tenant_id, ioc_type, normalized_value)` would silently allow
  unlimited duplicate *global* rows for the same indicator (every one
  of them having `tenant_id IS NULL`, and NULL never equals NULL).
  The partial indexes below close that gap explicitly:
    - uq_ioc_intelligence_iocs_global_identity: unique on
      (ioc_type, normalized_value) WHERE tenant_id IS NULL
    - uq_ioc_intelligence_iocs_tenant_identity: unique on
      (tenant_id, ioc_type, normalized_value) WHERE tenant_id IS NOT NULL
  Together these guarantee at most one global row and at most one row
  per distinct tenant for the same canonical indicator — and the same
  canonical value may legitimately have both a global row and any
  number of distinct tenants' own rows simultaneously, without
  collision.
- ioc_intelligence_source_attributions (dedup key: ioc_id +
  source_system + external_id, unique per IOC)
- ioc_intelligence_evidence_citations (dedup key: ioc_id + citation,
  unique per IOC)

No changes to any existing `threat_intel_*` table. No legacy data
migration, no dual-write.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0160"
down_revision: str = "0159"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ioc_intelligence_iocs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("ioc_type", sa.String(20), nullable=False),
        sa.Column("normalized_value", sa.String(2048), nullable=False),
        sa.Column("lifecycle", sa.String(16), nullable=False),
        sa.Column("epistemic_state", sa.String(16), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
    )
    op.create_index("ix_ioc_intelligence_iocs_tenant", "ioc_intelligence_iocs", ["tenant_id"])
    op.create_index("ix_ioc_intelligence_iocs_ioc_type", "ioc_intelligence_iocs", ["ioc_type"])
    op.create_index("ix_ioc_intelligence_iocs_lifecycle", "ioc_intelligence_iocs", ["lifecycle"])
    op.create_index(
        "ix_ioc_intelligence_iocs_epistemic_state", "ioc_intelligence_iocs", ["epistemic_state"]
    )
    op.create_index(
        "ix_ioc_intelligence_iocs_valid_until", "ioc_intelligence_iocs", ["valid_until"]
    )
    op.create_index(
        "uq_ioc_intelligence_iocs_global_identity",
        "ioc_intelligence_iocs",
        ["ioc_type", "normalized_value"],
        unique=True,
        postgresql_where=sa.text("tenant_id IS NULL"),
    )
    op.create_index(
        "uq_ioc_intelligence_iocs_tenant_identity",
        "ioc_intelligence_iocs",
        ["tenant_id", "ioc_type", "normalized_value"],
        unique=True,
        postgresql_where=sa.text("tenant_id IS NOT NULL"),
    )

    op.create_table(
        "ioc_intelligence_source_attributions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "ioc_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("ioc_intelligence_iocs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source_system", sa.String(64), nullable=False),
        sa.Column("external_id", sa.String(512), nullable=False),
        sa.Column("content_hash", sa.String(256), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("weight_applied", sa.Float(), nullable=False),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("attribution_metadata", postgresql.JSON(), nullable=False, server_default="{}"),
    )
    op.create_index(
        "ix_ioc_intelligence_source_attributions_ioc",
        "ioc_intelligence_source_attributions",
        ["ioc_id"],
    )
    op.create_index(
        "uq_ioc_intelligence_source_attributions_dedup",
        "ioc_intelligence_source_attributions",
        ["ioc_id", "source_system", "external_id"],
        unique=True,
    )

    op.create_table(
        "ioc_intelligence_evidence_citations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "ioc_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("ioc_intelligence_iocs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("citation", sa.String(2048), nullable=False),
    )
    op.create_index(
        "ix_ioc_intelligence_evidence_citations_ioc",
        "ioc_intelligence_evidence_citations",
        ["ioc_id"],
    )
    op.create_index(
        "uq_ioc_intelligence_evidence_citations_dedup",
        "ioc_intelligence_evidence_citations",
        ["ioc_id", "citation"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_table("ioc_intelligence_evidence_citations")
    op.drop_table("ioc_intelligence_source_attributions")
    op.drop_table("ioc_intelligence_iocs")
