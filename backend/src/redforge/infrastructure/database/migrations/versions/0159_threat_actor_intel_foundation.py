"""0159 — threat_actor_intel foundation tables (M51.1 Phase 3).

Migration chain: 0158 -> 0159.

Creates persistence for the two `threat_actor_intel` aggregate roots
(`ThreatActor`, `ThreatActorAssociation`) plus `ThreatActor`'s child
tables:

- threat_actor_intel_threat_actors (`tenant_id` NULLABLE — a global
  reference record per ADR-M51.1-02, never a reserved sentinel)
- threat_actor_intel_threat_actor_aliases
- threat_actor_intel_threat_actor_techniques
- threat_actor_intel_threat_actor_indicators
- threat_actor_intel_associations (`tenant_id` NOT NULL — always
  tenant-scoped per ADR-M51.1-03; a partial unique index enforces
  `AssociationUniquenessPolicy`'s invariant at the database level:
  exactly one ACTIVE row per (tenant_id, threat_actor_id,
  referenced_entity_type, referenced_entity_id))
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0159"
down_revision: str = "0158"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "threat_actor_intel_threat_actors",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("name", sa.String(512), nullable=False),
        sa.Column("origin", sa.String(32), nullable=False),
        sa.Column("sophistication", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("attribution_confidence", sa.String(16), nullable=False),
        sa.Column("motivations", postgresql.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
    )
    op.create_index(
        "ix_threat_actor_intel_threat_actors_tenant",
        "threat_actor_intel_threat_actors",
        ["tenant_id"],
    )
    op.create_index(
        "ix_threat_actor_intel_threat_actors_status",
        "threat_actor_intel_threat_actors",
        ["status"],
    )
    op.create_index(
        "ix_threat_actor_intel_threat_actors_origin",
        "threat_actor_intel_threat_actors",
        ["origin"],
    )

    op.create_table(
        "threat_actor_intel_threat_actor_aliases",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "threat_actor_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("threat_actor_intel_threat_actors.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("alias", sa.String(512), nullable=False),
    )
    op.create_index(
        "ix_threat_actor_intel_threat_actor_aliases_actor",
        "threat_actor_intel_threat_actor_aliases",
        ["threat_actor_id"],
    )

    op.create_table(
        "threat_actor_intel_threat_actor_techniques",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "threat_actor_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("threat_actor_intel_threat_actors.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("technique_id", sa.String(64), nullable=False),
    )
    op.create_index(
        "ix_threat_actor_intel_threat_actor_techniques_actor",
        "threat_actor_intel_threat_actor_techniques",
        ["threat_actor_id"],
    )
    op.create_index(
        "uq_threat_actor_intel_threat_actor_techniques_actor_technique",
        "threat_actor_intel_threat_actor_techniques",
        ["threat_actor_id", "technique_id"],
        unique=True,
    )

    op.create_table(
        "threat_actor_intel_threat_actor_indicators",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "threat_actor_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("threat_actor_intel_threat_actors.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("indicator_id", sa.String(256), nullable=False),
    )
    op.create_index(
        "ix_threat_actor_intel_threat_actor_indicators_actor",
        "threat_actor_intel_threat_actor_indicators",
        ["threat_actor_id"],
    )
    op.create_index(
        "uq_threat_actor_intel_threat_actor_indicators_actor_indicator",
        "threat_actor_intel_threat_actor_indicators",
        ["threat_actor_id", "indicator_id"],
        unique=True,
    )

    op.create_table(
        "threat_actor_intel_associations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "threat_actor_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("threat_actor_intel_threat_actors.id"),
            nullable=False,
        ),
        sa.Column("referenced_entity_type", sa.String(256), nullable=False),
        sa.Column("referenced_entity_id", sa.String(512), nullable=False),
        sa.Column("evidence_citation", sa.String(2048), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("retracted_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_threat_actor_intel_associations_tenant",
        "threat_actor_intel_associations",
        ["tenant_id"],
    )
    op.create_index(
        "ix_threat_actor_intel_associations_tenant_actor",
        "threat_actor_intel_associations",
        ["tenant_id", "threat_actor_id"],
    )
    op.create_index(
        "uq_threat_actor_intel_associations_active_tuple",
        "threat_actor_intel_associations",
        ["tenant_id", "threat_actor_id", "referenced_entity_type", "referenced_entity_id"],
        unique=True,
        postgresql_where=sa.text("state = 'active'"),
    )


def downgrade() -> None:
    op.drop_table("threat_actor_intel_associations")
    op.drop_table("threat_actor_intel_threat_actor_indicators")
    op.drop_table("threat_actor_intel_threat_actor_techniques")
    op.drop_table("threat_actor_intel_threat_actor_aliases")
    op.drop_table("threat_actor_intel_threat_actors")
