"""0041 — Organization Assessment Domain (M24 Phase 2).

Creates:
  compliance_profiles
  assessment_periods
  control_assessments

Control status is stored as VARCHAR (never a DB enum) so future lifecycle
states remain forward-compatible and unknown values are never rewritten.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0041"
down_revision: str = "0040"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "compliance_profiles",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "framework_keys",
            postgresql.ARRAY(sa.String(80)),
            nullable=False,
            server_default="{}",
        ),
        sa.Column("status", sa.String(20), nullable=False, server_default="draft"),
        sa.Column("created_by", sa.String(26), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "organization_id",
            "name",
            name="uq_compliance_profiles_org_name",
        ),
    )
    op.create_index(
        "ix_compliance_profiles_org_status",
        "compliance_profiles",
        ["organization_id", "status"],
    )

    op.create_table(
        "assessment_periods",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("profile_id", sa.String(26), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("framework_key", sa.String(80), nullable=False),
        sa.Column("period_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("period_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="planned"),
        sa.Column("created_by", sa.String(26), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "organization_id",
            "profile_id",
            "name",
            name="uq_assessment_periods_org_profile_name",
        ),
    )
    op.create_index(
        "ix_assessment_periods_org_profile",
        "assessment_periods",
        ["organization_id", "profile_id"],
    )
    op.create_index(
        "ix_assessment_periods_org_status",
        "assessment_periods",
        ["organization_id", "status"],
    )

    op.create_table(
        "control_assessments",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("profile_id", sa.String(26), nullable=False),
        sa.Column("period_id", sa.String(26), nullable=False),
        sa.Column("requirement_id", sa.String(26), nullable=False),
        sa.Column("framework_key", sa.String(80), nullable=False),
        # VARCHAR — never a PostgreSQL ENUM (forward-compatible lifecycle).
        sa.Column(
            "status",
            sa.String(64),
            nullable=False,
            server_default="not_assessed",
        ),
        sa.Column(
            "evidence_links",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_by", sa.String(26), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "organization_id",
            "period_id",
            "requirement_id",
            name="uq_control_assessments_org_period_req",
        ),
    )
    op.create_index(
        "ix_control_assessments_org_period",
        "control_assessments",
        ["organization_id", "period_id"],
    )
    op.create_index(
        "ix_control_assessments_org_status",
        "control_assessments",
        ["organization_id", "status"],
    )


def downgrade() -> None:
    op.drop_index("ix_control_assessments_org_status", table_name="control_assessments")
    op.drop_index("ix_control_assessments_org_period", table_name="control_assessments")
    op.drop_table("control_assessments")
    op.drop_index("ix_assessment_periods_org_status", table_name="assessment_periods")
    op.drop_index("ix_assessment_periods_org_profile", table_name="assessment_periods")
    op.drop_table("assessment_periods")
    op.drop_index("ix_compliance_profiles_org_status", table_name="compliance_profiles")
    op.drop_table("compliance_profiles")
