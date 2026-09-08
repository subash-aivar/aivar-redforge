"""0165 — tool_intel foundation tables.

Migration chain: 0164 -> 0165.

Creates persistence for the `Tool` aggregate root (a threat-intel record
of an ADVERSARY TOOL — e.g. Mimikatz, Cobalt Strike, PsExec — unrelated
to AI-agent function/tool-calling in `redforge.domain.agents`) plus its
six owned child collections. New tables only — no changes to any
existing table.

- tool_intel_tools (`tenant_id` NULLABLE — `NULL` is a genuine global
  RedForge-curated record, never a reserved sentinel). Canonical
  identity is `canonical_name` (strongly normalized in the domain),
  scoped by ownership via two PARTIAL unique indexes — the same
  NULL-is-distinct-from-NULL-aware split migration 0164 already
  established for `campaign_intel_campaigns`:
    - uq_tool_intel_global_identity: unique on (canonical_name)
      WHERE tenant_id IS NULL
    - uq_tool_intel_tenant_identity: unique on
      (tenant_id, canonical_name) WHERE tenant_id IS NOT NULL
  `family_name` is nullable — a tool need not belong to any family.
- tool_intel_aliases (child, cascade delete)
- tool_intel_platforms (child, cascade delete, unique per tool)
- tool_intel_capabilities (child, cascade delete, unique per tool)
- tool_intel_evidence_citations (child, cascade delete)
- tool_intel_source_attributions (child, cascade delete)
- tool_intel_version_history (child, cascade delete, append-only —
  dedup key: tool_id + version, unique per tool)

No relationship table: cross-entity relationships involving tools are
owned exclusively by the `intelligence_relationships` bounded context
(migration 0162), whose `TOOL` entity type references a `Tool` by
opaque `entity_id` (see `TOOL_TO_THREAT_ACTOR` and `IOC_TO_TOOL`).

No legacy data migration, no dual-write.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0165"
down_revision: str = "0164"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "tool_intel_tools",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("canonical_name", sa.String(300), nullable=False),
        sa.Column("category", sa.String(48), nullable=False),
        sa.Column("lifecycle_status", sa.String(16), nullable=False),
        sa.Column("family_name", sa.String(300), nullable=True),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("superseded_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
    )
    op.create_index("ix_tool_intel_tools_tenant", "tool_intel_tools", ["tenant_id"])
    op.create_index("ix_tool_intel_tools_canonical_name", "tool_intel_tools", ["canonical_name"])
    op.create_index("ix_tool_intel_tools_lifecycle", "tool_intel_tools", ["lifecycle_status"])
    op.create_index("ix_tool_intel_tools_category", "tool_intel_tools", ["category"])
    op.create_index("ix_tool_intel_tools_family", "tool_intel_tools", ["family_name"])
    op.create_index(
        "uq_tool_intel_global_identity",
        "tool_intel_tools",
        ["canonical_name"],
        unique=True,
        postgresql_where=sa.text("tenant_id IS NULL"),
    )
    op.create_index(
        "uq_tool_intel_tenant_identity",
        "tool_intel_tools",
        ["tenant_id", "canonical_name"],
        unique=True,
        postgresql_where=sa.text("tenant_id IS NOT NULL"),
    )

    op.create_table(
        "tool_intel_aliases",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tool_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tool_intel_tools.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("value", sa.String(300), nullable=False),
    )
    op.create_index("ix_tool_intel_aliases_tool", "tool_intel_aliases", ["tool_id"])

    op.create_table(
        "tool_intel_platforms",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tool_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tool_intel_tools.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("platform", sa.String(32), nullable=False),
    )
    op.create_index("ix_tool_intel_platforms_tool", "tool_intel_platforms", ["tool_id"])
    op.create_index(
        "uq_tool_intel_platforms_dedup",
        "tool_intel_platforms",
        ["tool_id", "platform"],
        unique=True,
    )

    op.create_table(
        "tool_intel_capabilities",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tool_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tool_intel_tools.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("capability", sa.String(32), nullable=False),
    )
    op.create_index("ix_tool_intel_capabilities_tool", "tool_intel_capabilities", ["tool_id"])
    op.create_index(
        "uq_tool_intel_capabilities_dedup",
        "tool_intel_capabilities",
        ["tool_id", "capability"],
        unique=True,
    )

    op.create_table(
        "tool_intel_evidence_citations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tool_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tool_intel_tools.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("value", sa.Text(), nullable=False),
    )
    op.create_index(
        "ix_tool_intel_evidence_citations_tool", "tool_intel_evidence_citations", ["tool_id"]
    )

    op.create_table(
        "tool_intel_source_attributions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tool_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tool_intel_tools.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source_system", sa.String(128), nullable=False),
        sa.Column("reference", sa.String(512), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index(
        "ix_tool_intel_source_attributions_tool", "tool_intel_source_attributions", ["tool_id"]
    )

    op.create_table(
        "tool_intel_version_history",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tool_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tool_intel_tools.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("change_summary", sa.Text(), nullable=False),
        sa.Column("source", sa.String(128), nullable=False),
    )
    op.create_index("ix_tool_intel_version_history_tool", "tool_intel_version_history", ["tool_id"])
    op.create_index(
        "uq_tool_intel_version_history_dedup",
        "tool_intel_version_history",
        ["tool_id", "version"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_table("tool_intel_version_history")
    op.drop_table("tool_intel_source_attributions")
    op.drop_table("tool_intel_evidence_citations")
    op.drop_table("tool_intel_capabilities")
    op.drop_table("tool_intel_platforms")
    op.drop_table("tool_intel_aliases")
    op.drop_table("tool_intel_tools")
