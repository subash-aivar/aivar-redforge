"""Security Correlation foundation — M9.

Adds:
  - security_correlations: canonical deterministic correlations,
    deduplicated via `identity_key` (stable rule ID + rule version +
    sorted canonical entity IDs — NEVER title/summary/operator_action).
  - security_correlation_conditions: normalized association between a
    correlation and the SecurityCondition rows that support it —
    modeled as a real table (not a JSON blob) because source condition
    IDs are first-class canonical references requiring tenant-safe
    referential integrity, not presentation-only data.
  - security_correlation_entities: normalized association between a
    correlation and the canonical AIAsset rows it concerns — same
    reasoning as above.

Both association tables carry `organization_id` and a composite FK to
the parent's `(id, organization_id)`, plus a composite FK to the
referenced row's `(id, organization_id)` — a cross-tenant association
is a physical FK violation, not an application-level check, mirroring
the M4/M5/M6/M7/M8 pattern.

Revision ID: 0017
"""

import sqlalchemy as sa
from alembic import op

revision: str = "0017"
down_revision: str = "0016"
branch_labels: None = None
depends_on: None = None


def upgrade() -> None:
    op.create_table(
        "security_correlations",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("stable_rule_id", sa.String(100), nullable=False),
        sa.Column("rule_version", sa.Integer, nullable=False),
        sa.Column("identity_key", sa.String(600), nullable=False),
        sa.Column("evidence_state", sa.String(20), nullable=False),
        sa.Column("lifecycle", sa.String(20), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("summary", sa.String(1000), nullable=False),
        sa.Column("operator_action", sa.String(1000), nullable=False, server_default=""),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("version", sa.Integer, nullable=False, server_default="1"),
        sa.UniqueConstraint("id", "organization_id", name="ux_sec_correlations_id_org"),
    )
    op.create_index(
        "ix_sec_correlations_organization_id", "security_correlations", ["organization_id"],
    )
    op.create_index(
        "ix_sec_correlations_org_lifecycle", "security_correlations",
        ["organization_id", "lifecycle"],
    )
    op.create_index(
        "ix_sec_correlations_org_rule", "security_correlations",
        ["organization_id", "stable_rule_id"],
    )
    op.create_index(
        "ux_sec_correlations_org_identity", "security_correlations",
        ["organization_id", "identity_key"], unique=True,
    )

    op.create_table(
        "security_correlation_conditions",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("correlation_id", sa.String(26), nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("security_condition_id", sa.String(26), nullable=False),
        sa.ForeignKeyConstraint(
            ["correlation_id", "organization_id"],
            ["security_correlations.id", "security_correlations.organization_id"],
            name="fk_sec_corr_cond_correlation_same_tenant",
        ),
        sa.ForeignKeyConstraint(
            ["security_condition_id", "organization_id"],
            ["security_conditions.id", "security_conditions.organization_id"],
            name="fk_sec_corr_cond_condition_same_tenant",
        ),
        sa.UniqueConstraint(
            "correlation_id", "security_condition_id", name="ux_sec_corr_cond_pair",
        ),
    )
    op.create_index(
        "ix_sec_corr_cond_correlation_id", "security_correlation_conditions", ["correlation_id"],
    )
    op.create_index(
        "ix_sec_corr_cond_organization_id", "security_correlation_conditions", ["organization_id"],
    )

    op.create_table(
        "security_correlation_entities",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("correlation_id", sa.String(26), nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("asset_id", sa.String(26), nullable=False),
        sa.ForeignKeyConstraint(
            ["correlation_id", "organization_id"],
            ["security_correlations.id", "security_correlations.organization_id"],
            name="fk_sec_corr_entity_correlation_same_tenant",
        ),
        sa.ForeignKeyConstraint(
            ["asset_id", "organization_id"],
            ["ai_assets.id", "ai_assets.organization_id"],
            name="fk_sec_corr_entity_asset_same_tenant",
        ),
        sa.UniqueConstraint("correlation_id", "asset_id", name="ux_sec_corr_entity_pair"),
    )
    op.create_index(
        "ix_sec_corr_entity_correlation_id", "security_correlation_entities", ["correlation_id"],
    )
    op.create_index(
        "ix_sec_corr_entity_organization_id", "security_correlation_entities", ["organization_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_sec_corr_entity_organization_id", table_name="security_correlation_entities",
    )
    op.drop_index(
        "ix_sec_corr_entity_correlation_id", table_name="security_correlation_entities",
    )
    op.drop_table("security_correlation_entities")

    op.drop_index("ix_sec_corr_cond_organization_id", table_name="security_correlation_conditions")
    op.drop_index("ix_sec_corr_cond_correlation_id", table_name="security_correlation_conditions")
    op.drop_table("security_correlation_conditions")

    op.drop_index("ux_sec_correlations_org_identity", table_name="security_correlations")
    op.drop_index("ix_sec_correlations_org_rule", table_name="security_correlations")
    op.drop_index("ix_sec_correlations_org_lifecycle", table_name="security_correlations")
    op.drop_index("ix_sec_correlations_organization_id", table_name="security_correlations")
    op.drop_table("security_correlations")
