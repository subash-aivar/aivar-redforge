"""0040 — Compliance Control Catalog (M24 Phase 1).

Creates three tables:
  compliance_frameworks    — FrameworkDefinition (key, status, metadata)
  compliance_requirements  — ControlRequirement (per-framework controls)
  compliance_mappings      — ControlMapping (cross-framework relationships)

No organization_id columns — this is platform-owned data.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0040"
down_revision: str = "0039"
branch_labels: None = None
depends_on: None = None


def upgrade() -> None:
    op.create_table(
        "compliance_frameworks",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("key", sa.String(80), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="draft"),
        sa.Column("metadata", postgresql.JSONB, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_unique_constraint("uq_cf_key", "compliance_frameworks", ["key"])
    op.create_index("ix_cf_status", "compliance_frameworks", ["status"])

    op.create_table(
        "compliance_requirements",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("framework_key", sa.String(80), nullable=False),
        sa.Column("requirement_ref", sa.String(80), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("domain", sa.String(50), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("guidance", sa.Text, nullable=False, server_default=""),
        sa.Column("policy_threshold", sa.Integer, nullable=False, server_default="80"),
        sa.Column(
            "tags",
            postgresql.ARRAY(sa.String),
            nullable=False,
            server_default="{}",
        ),
        sa.Column("external_ref", sa.Text, nullable=False, server_default=""),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_unique_constraint(
        "uq_cr_fw_ref",
        "compliance_requirements",
        ["framework_key", "requirement_ref"],
    )
    op.create_index("ix_cr_framework_key", "compliance_requirements", ["framework_key"])
    op.create_index("ix_cr_domain", "compliance_requirements", ["domain"])
    op.create_index("ix_cr_severity", "compliance_requirements", ["severity"])

    op.create_table(
        "compliance_mappings",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("source_requirement_id", sa.String(26), nullable=False),
        sa.Column("target_requirement_id", sa.String(26), nullable=False),
        sa.Column("source_framework_key", sa.String(80), nullable=False),
        sa.Column("target_framework_key", sa.String(80), nullable=False),
        sa.Column("confidence", sa.String(20), nullable=False),
        sa.Column("rationale", sa.Text, nullable=False, server_default=""),
        sa.Column("version", sa.String(20), nullable=False, server_default="1.0"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default="true"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_unique_constraint(
        "uq_cm_src_tgt_active",
        "compliance_mappings",
        ["source_requirement_id", "target_requirement_id", "is_active"],
    )
    op.create_index("ix_cm_source_fw", "compliance_mappings", ["source_framework_key"])
    op.create_index("ix_cm_target_fw", "compliance_mappings", ["target_framework_key"])
    op.create_index("ix_cm_is_active", "compliance_mappings", ["is_active"])


def downgrade() -> None:
    op.drop_table("compliance_mappings")
    op.drop_table("compliance_requirements")
    op.drop_table("compliance_frameworks")
