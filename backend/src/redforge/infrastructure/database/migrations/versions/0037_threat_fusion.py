"""Threat Fusion — M22 Phase 4.

Schema-only. Consumes Phase 1 reference-data / Phase 3 STIX outputs via
the application layer — no bulk seed data.

Tables:
  1. fused_indicators — canonical fused intelligence indicators
     (technique/tactic/vulnerability/software/campaign/group/mitigation)
     with lifecycle, temporal validity, and AggregatedRisk snapshot.
  2. fused_indicator_sources — per-source provenance rows (attributions).
  3. fused_relationships — resolved correlation edges between fused
     indicators (from ATT&CK/STIX relationships).
  4. threat_intel_fusion_config — admin overrides of default source
     weights (platform-global; reference data itself is global).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0037"
down_revision: str = "0036"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "fused_indicators",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("canonical_key", sa.String(300), nullable=False),
        sa.Column("indicator_type", sa.String(30), nullable=False),
        sa.Column("display_name", sa.String(512), nullable=False),
        sa.Column("lifecycle", sa.String(20), nullable=False, server_default="active"),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("risk_state", sa.String(20), nullable=False),
        sa.Column("confidence", sa.String(20), nullable=True),
        sa.Column("winner_source_system", sa.String(30), nullable=True),
        sa.Column(
            "risk_breakdown",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("canonical_key", name="ux_fused_indicators_canonical_key"),
    )
    op.create_index(
        "ix_fused_indicators_type_lifecycle",
        "fused_indicators",
        ["indicator_type", "lifecycle"],
    )
    op.create_index(
        "ix_fused_indicators_confidence",
        "fused_indicators",
        ["confidence"],
    )

    op.create_table(
        "fused_indicator_sources",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column(
            "indicator_id",
            sa.String(26),
            sa.ForeignKey("fused_indicators.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source_system", sa.String(30), nullable=False),
        sa.Column("external_id", sa.String(256), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("weight_applied", sa.Float, nullable=False),
        sa.Column("confidence", sa.String(20), nullable=False),
        sa.Column("feed_id", sa.String(26), nullable=True),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.UniqueConstraint(
            "indicator_id",
            "source_system",
            "external_id",
            name="ux_fused_sources_indicator_source_external",
        ),
    )
    op.create_index(
        "ix_fused_sources_indicator",
        "fused_indicator_sources",
        ["indicator_id"],
    )

    op.create_table(
        "fused_relationships",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("relationship_type", sa.String(64), nullable=False),
        sa.Column(
            "source_indicator_id",
            sa.String(26),
            sa.ForeignKey("fused_indicators.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "target_indicator_id",
            sa.String(26),
            sa.ForeignKey("fused_indicators.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source_canonical_key", sa.String(300), nullable=False),
        sa.Column("target_canonical_key", sa.String(300), nullable=False),
        sa.Column("stix_relationship_id", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "stix_relationship_id",
            name="ux_fused_relationships_stix_id",
        ),
    )
    op.create_index(
        "ix_fused_rel_source",
        "fused_relationships",
        ["source_indicator_id"],
    )
    op.create_index(
        "ix_fused_rel_target",
        "fused_relationships",
        ["target_indicator_id"],
    )
    op.create_index(
        "ix_fused_rel_type",
        "fused_relationships",
        ["relationship_type"],
    )

    op.create_table(
        "threat_intel_fusion_config",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("source_system", sa.String(30), nullable=False),
        sa.Column("weight", sa.Float, nullable=False),
        sa.Column("updated_by", sa.String(26), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "source_system", name="ux_fusion_config_source_system"
        ),
        sa.CheckConstraint(
            "weight > 0 AND weight <= 1", name="ck_fusion_config_weight_range"
        ),
    )


def downgrade() -> None:
    op.drop_table("threat_intel_fusion_config")
    op.drop_table("fused_relationships")
    op.drop_table("fused_indicator_sources")
    op.drop_table("fused_indicators")
