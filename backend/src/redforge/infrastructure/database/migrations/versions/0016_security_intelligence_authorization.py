"""Security Condition foundation — M8.

Adds:
  - `ux_ai_assets_id_org` (M3's `ai_assets` table gets its first
    composite-FK-target unique constraint — needed so
    `security_conditions.affected_asset_id` can be DB-enforced
    same-tenant, the same pattern M4/M5/M6/M7 already established for
    security_graph_nodes/directory_identities/directory_groups).
  - security_conditions (M8): canonical deterministic security
    conditions, deduplicated via `identity_key` (organization +
    affected asset + source category + stable rule ID + qualifier —
    NEVER title/summary/remediation).

Principal review note (M8 completion pass): this revision originally
also scaffolded `security_correlations` (M9) and
`security_authorizations`/`security_authorization_scope`/
`security_authorization_decisions` (M10) ahead of those milestones'
actual implementation. Since M9/M10 are not yet implemented and no
application code referenced those tables, they were removed from this
revision rather than left as unreviewed speculative schema — M9/M10
will introduce their own migrations against real, implemented
architecture when those milestones begin.

Revision ID: 0016
"""

import sqlalchemy as sa
from alembic import op

revision: str = "0016"
down_revision: str = "0015"
branch_labels: None = None
depends_on: None = None


def upgrade() -> None:
    op.create_unique_constraint("ux_ai_assets_id_org", "ai_assets", ["id", "organization_id"])

    op.create_table(
        "security_conditions",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("affected_asset_id", sa.String(26), nullable=False),
        sa.Column("source_category", sa.String(30), nullable=False),
        sa.Column("stable_rule_id", sa.String(100), nullable=False),
        sa.Column("qualifier", sa.String(100), nullable=False, server_default=""),
        sa.Column("identity_key", sa.String(400), nullable=False),
        sa.Column("evidence_state", sa.String(20), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("summary", sa.String(1000), nullable=False),
        sa.Column("remediation", sa.String(1000), nullable=False, server_default=""),
        sa.Column("canonical_references", sa.JSON, nullable=False),
        sa.Column("evidence", sa.JSON, nullable=False),
        sa.Column("lifecycle", sa.String(20), nullable=False),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer, nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(
            ["affected_asset_id", "organization_id"],
            ["ai_assets.id", "ai_assets.organization_id"],
            name="fk_sec_condition_asset_same_tenant",
        ),
        sa.UniqueConstraint("id", "organization_id", name="ux_sec_conditions_id_org"),
    )
    op.create_index(
        "ix_sec_conditions_organization_id", "security_conditions", ["organization_id"],
    )
    op.create_index(
        "ix_sec_conditions_org_asset", "security_conditions",
        ["organization_id", "affected_asset_id"],
    )
    op.create_index(
        "ix_sec_conditions_org_state", "security_conditions", ["organization_id", "evidence_state"],
    )
    op.create_index(
        "ux_sec_conditions_org_identity",
        "security_conditions",
        ["organization_id", "identity_key"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ux_sec_conditions_org_identity", table_name="security_conditions")
    op.drop_index("ix_sec_conditions_org_state", table_name="security_conditions")
    op.drop_index("ix_sec_conditions_org_asset", table_name="security_conditions")
    op.drop_index("ix_sec_conditions_organization_id", table_name="security_conditions")
    op.drop_table("security_conditions")

    op.drop_constraint("ux_ai_assets_id_org", "ai_assets", type_="unique")
