"""0161 — attack_pattern_intel foundation tables (M51.3 Phase B1).

Migration chain: 0160 -> 0161.

Creates persistence for the `AttackPattern` aggregate root plus its
five owned child collections. New tables only — no changes to any
existing `attack_techniques`/`attack_tactics`/
`attack_technique_relationships` table (M22, DO-NOT-MODIFY). Identity
references those canonical tables only by opaque
`technique_id`/`sub_technique_id` string columns — no foreign key
crosses the bounded-context boundary.

- attack_pattern_intel_patterns (`tenant_id` NULLABLE — `NULL` is a
  genuine global RedForge-curated record, never a reserved sentinel).
  Canonical identity is `(technique_id, sub_technique_id)`, scoped by
  ownership via two PARTIAL unique indexes — the same
  NULL-is-distinct-from-NULL-aware split migration 0160 already
  established for `ioc_intelligence_iocs`:
    - uq_attack_pattern_intel_global_identity: unique on
      (technique_id, sub_technique_id) WHERE tenant_id IS NULL
    - uq_attack_pattern_intel_tenant_identity: unique on
      (tenant_id, technique_id, sub_technique_id) WHERE tenant_id IS
      NOT NULL
- attack_pattern_intel_detection_guidance (child, cascade delete)
- attack_pattern_intel_mitigation_references (child, cascade delete)
- attack_pattern_intel_procedure_examples (child, cascade delete)
- attack_pattern_intel_relationships (child, cascade delete)
- attack_pattern_intel_version_history (child, cascade delete,
  append-only — dedup key: attack_pattern_id + version, unique per
  pattern)

No legacy data migration, no dual-write.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0161"
down_revision: str = "0160"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "attack_pattern_intel_patterns",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("technique_id", sa.String(20), nullable=False),
        sa.Column("sub_technique_id", sa.String(20), nullable=True),
        sa.Column("lifecycle_status", sa.String(16), nullable=False),
        sa.Column("superseded_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("tactic_mappings", postgresql.JSON(), nullable=False, server_default="[]"),
        sa.Column("platforms", postgresql.JSON(), nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
    )
    op.create_index(
        "ix_attack_pattern_intel_patterns_tenant", "attack_pattern_intel_patterns", ["tenant_id"]
    )
    op.create_index(
        "ix_attack_pattern_intel_patterns_technique_id",
        "attack_pattern_intel_patterns",
        ["technique_id"],
    )
    op.create_index(
        "ix_attack_pattern_intel_patterns_lifecycle",
        "attack_pattern_intel_patterns",
        ["lifecycle_status"],
    )
    op.create_index(
        "uq_attack_pattern_intel_global_identity",
        "attack_pattern_intel_patterns",
        ["technique_id", "sub_technique_id"],
        unique=True,
        postgresql_where=sa.text("tenant_id IS NULL"),
    )
    op.create_index(
        "uq_attack_pattern_intel_tenant_identity",
        "attack_pattern_intel_patterns",
        ["tenant_id", "technique_id", "sub_technique_id"],
        unique=True,
        postgresql_where=sa.text("tenant_id IS NOT NULL"),
    )

    op.create_table(
        "attack_pattern_intel_detection_guidance",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "attack_pattern_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("attack_pattern_intel_patterns.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("source_system", sa.String(128), nullable=False),
        sa.Column("reference", sa.String(512), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index(
        "ix_attack_pattern_intel_detection_guidance_pattern",
        "attack_pattern_intel_detection_guidance",
        ["attack_pattern_id"],
    )

    op.create_table(
        "attack_pattern_intel_mitigation_references",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "attack_pattern_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("attack_pattern_intel_patterns.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("mitigation_id", sa.String(64), nullable=False),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("source_system", sa.String(128), nullable=False),
        sa.Column("reference", sa.String(512), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index(
        "ix_attack_pattern_intel_mitigation_references_pattern",
        "attack_pattern_intel_mitigation_references",
        ["attack_pattern_id"],
    )

    op.create_table(
        "attack_pattern_intel_procedure_examples",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "attack_pattern_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("attack_pattern_intel_patterns.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("actor_ref", sa.String(300), nullable=True),
        sa.Column("source_system", sa.String(128), nullable=False),
        sa.Column("reference", sa.String(512), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index(
        "ix_attack_pattern_intel_procedure_examples_pattern",
        "attack_pattern_intel_procedure_examples",
        ["attack_pattern_id"],
    )

    op.create_table(
        "attack_pattern_intel_relationships",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "attack_pattern_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("attack_pattern_intel_patterns.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("relationship_type", sa.String(64), nullable=False),
        sa.Column("target_attack_pattern_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_system", sa.String(128), nullable=False),
        sa.Column("reference", sa.String(512), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index(
        "ix_attack_pattern_intel_relationships_pattern",
        "attack_pattern_intel_relationships",
        ["attack_pattern_id"],
    )

    op.create_table(
        "attack_pattern_intel_version_history",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "attack_pattern_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("attack_pattern_intel_patterns.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("change_summary", sa.Text(), nullable=False),
        sa.Column("source", sa.String(128), nullable=False),
    )
    op.create_index(
        "ix_attack_pattern_intel_version_history_pattern",
        "attack_pattern_intel_version_history",
        ["attack_pattern_id"],
    )
    op.create_index(
        "uq_attack_pattern_intel_version_history_dedup",
        "attack_pattern_intel_version_history",
        ["attack_pattern_id", "version"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_table("attack_pattern_intel_version_history")
    op.drop_table("attack_pattern_intel_relationships")
    op.drop_table("attack_pattern_intel_procedure_examples")
    op.drop_table("attack_pattern_intel_mitigation_references")
    op.drop_table("attack_pattern_intel_detection_guidance")
    op.drop_table("attack_pattern_intel_patterns")
