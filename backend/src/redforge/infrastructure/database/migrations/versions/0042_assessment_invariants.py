"""0042 — M24 Phase 2 mandatory invariants.

1. Active framework claim table: at most one active ComplianceProfile
   may claim a given (organization_id, framework_key).
2. Period-close invariant is enforced in the domain (no schema change).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0042"
down_revision: str = "0041"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "compliance_active_framework_claims",
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("framework_key", sa.String(80), nullable=False),
        sa.Column("profile_id", sa.String(26), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint(
            "organization_id",
            "framework_key",
            name="pk_compliance_active_framework_claims",
        ),
    )
    op.create_index(
        "ix_cafc_profile",
        "compliance_active_framework_claims",
        ["organization_id", "profile_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_cafc_profile", table_name="compliance_active_framework_claims")
    op.drop_table("compliance_active_framework_claims")
