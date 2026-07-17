"""Attack Path Engine — M22 Phase 5.

Schema-only. Paths are tenant-scoped; steps are a separate child table
with unique (attack_path_id, sequence). Evidence refs use a join table
(Hardening Review: prefer join table over unbounded string arrays).

Tables:
  1. attack_paths — aggregate summary (no embedded step collection)
  2. attack_path_steps — ordered steps for one path
  3. attack_path_step_evidence — evidence ref join rows per step
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0038"
down_revision: str = "0037"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "attack_paths",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("root_entity_id", sa.String(26), nullable=False),
        sa.Column("root_canonical_key", sa.String(300), nullable=False),
        sa.Column("terminal_entity_id", sa.String(26), nullable=True),
        sa.Column("path_confidence", sa.String(20), nullable=False),
        sa.Column("technique_coverage", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("attributed_actors", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("step_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("evidence_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("max_exposure_score", sa.Float, nullable=False, server_default="0"),
        sa.Column("first_step_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_step_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_attack_paths_org_status",
        "attack_paths",
        ["organization_id", "status"],
    )
    op.create_index(
        "ix_attack_paths_org_root_entity",
        "attack_paths",
        ["organization_id", "root_entity_id"],
    )
    op.create_index(
        "ix_attack_paths_org_confidence",
        "attack_paths",
        ["organization_id", "path_confidence"],
    )
    # Partial index supporting "by root technique" queries without a
    # cross-aggregate join explosion — technique_coverage is JSON, so
    # callers filter in application code after org-scoped fetch; the
    # org+status index above is the mandatory tenant backstop
    # (Hardening Review P1 on find_by_root_technique).

    op.create_table(
        "attack_path_steps",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column(
            "attack_path_id",
            sa.String(26),
            sa.ForeignKey("attack_paths.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("sequence", sa.Integer, nullable=False),
        sa.Column("entity_id", sa.String(26), nullable=False),
        sa.Column("canonical_key", sa.String(300), nullable=False),
        sa.Column("step_type", sa.String(20), nullable=False),
        sa.Column("confidence", sa.String(20), nullable=False),
        sa.Column("technique_id", sa.String(32), nullable=True),
        sa.Column("relationship_type", sa.String(64), nullable=True),
        sa.Column("kill_chain_phase", sa.String(64), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("inferred_from_step", sa.Integer, nullable=True),
        sa.Column("exposure_score", sa.Float, nullable=False, server_default="0"),
        sa.UniqueConstraint(
            "attack_path_id",
            "sequence",
            name="ux_attack_path_steps_path_sequence",
        ),
    )
    op.create_index(
        "ix_attack_path_steps_path",
        "attack_path_steps",
        ["attack_path_id"],
    )
    op.create_index(
        "ix_attack_path_steps_org",
        "attack_path_steps",
        ["organization_id"],
    )

    op.create_table(
        "attack_path_step_evidence",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column(
            "step_id",
            sa.String(26),
            sa.ForeignKey("attack_path_steps.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("evidence_ref", sa.String(128), nullable=False),
        sa.UniqueConstraint(
            "step_id",
            "evidence_ref",
            name="ux_attack_path_step_evidence_step_ref",
        ),
    )
    op.create_index(
        "ix_attack_path_step_evidence_step",
        "attack_path_step_evidence",
        ["step_id"],
    )


def downgrade() -> None:
    op.drop_table("attack_path_step_evidence")
    op.drop_table("attack_path_steps")
    op.drop_table("attack_paths")
