"""Directory & Identity Security Visibility foundation — M5.

Adds:
  - directory_identities: canonical, tenant-owned, CONNECTOR-scoped
    observed directory principals (human or non-human). Identity
    resolution key is (organization_id, connector_id, external_id) —
    connector is part of the uniqueness key (not just org+external_id
    as M3's asset identity is), because two independent directories
    could theoretically expose the same raw source identifier; scoping
    per-connector avoids silently merging two distinct real-world
    principals from different sources.
  - directory_groups: same key pattern for observed directory groups.
  - directory_memberships: DIRECT identity->group membership only in
    M5 (nested group->group membership is an honestly deferred P1 —
    see the M5 report). Tenant integrity for both endpoints is
    enforced at the DATABASE level via composite foreign keys
    (id, organization_id), the same pattern M4 established for
    security_graph_edges — a membership row whose identity_id or
    group_id belongs to a different organization than the membership
    itself is a physical foreign-key violation.

Revision ID: 0015
"""

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: str = "0014"
branch_labels: None = None
depends_on: None = None


def upgrade() -> None:
    op.create_table(
        "directory_identities",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("connector_id", sa.String(26), nullable=False),
        sa.Column("external_id", sa.String(255), nullable=False),
        sa.Column("principal_category", sa.String(20), nullable=False),
        sa.Column("display_name", sa.String(255), nullable=False),
        sa.Column("principal_name", sa.String(255), nullable=False, server_default=""),
        sa.Column("source_enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("privilege_classification", sa.String(20), nullable=False),
        sa.Column("privilege_reason", sa.String(255), nullable=False, server_default=""),
        sa.Column("observation_lifecycle", sa.String(20), nullable=False),
        sa.Column("safe_attributes", sa.JSON, nullable=False),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer, nullable=False, server_default="1"),
        sa.UniqueConstraint("id", "organization_id", name="ux_dir_identities_id_org"),
    )
    op.create_index(
        "ix_dir_identities_organization_id", "directory_identities", ["organization_id"],
    )
    op.create_index(
        "ix_dir_identities_org_privilege",
        "directory_identities",
        ["organization_id", "privilege_classification"],
    )
    op.create_index(
        "ux_dir_identities_org_connector_external",
        "directory_identities",
        ["organization_id", "connector_id", "external_id"],
        unique=True,
    )

    op.create_table(
        "directory_groups",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("connector_id", sa.String(26), nullable=False),
        sa.Column("external_id", sa.String(255), nullable=False),
        sa.Column("display_name", sa.String(255), nullable=False),
        sa.Column(
            "is_recognized_privileged", sa.Boolean, nullable=False, server_default=sa.false(),
        ),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer, nullable=False, server_default="1"),
        sa.UniqueConstraint("id", "organization_id", name="ux_dir_groups_id_org"),
    )
    op.create_index("ix_dir_groups_organization_id", "directory_groups", ["organization_id"])
    op.create_index(
        "ux_dir_groups_org_connector_external",
        "directory_groups",
        ["organization_id", "connector_id", "external_id"],
        unique=True,
    )

    op.create_table(
        "directory_memberships",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("identity_id", sa.String(26), nullable=False),
        sa.Column("group_id", sa.String(26), nullable=False),
        sa.Column("provenance", sa.String(100), nullable=False),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer, nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(
            ["identity_id", "organization_id"],
            ["directory_identities.id", "directory_identities.organization_id"],
            name="fk_dir_membership_identity_same_tenant",
        ),
        sa.ForeignKeyConstraint(
            ["group_id", "organization_id"],
            ["directory_groups.id", "directory_groups.organization_id"],
            name="fk_dir_membership_group_same_tenant",
        ),
    )
    op.create_index(
        "ix_dir_memberships_organization_id", "directory_memberships", ["organization_id"],
    )
    op.create_index(
        "ix_dir_memberships_identity_id", "directory_memberships", ["identity_id"],
    )
    op.create_index(
        "ix_dir_memberships_group_id", "directory_memberships", ["group_id"],
    )
    op.create_index(
        "ux_dir_memberships_org_identity_group",
        "directory_memberships",
        ["organization_id", "identity_id", "group_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ux_dir_memberships_org_identity_group", table_name="directory_memberships")
    op.drop_index("ix_dir_memberships_group_id", table_name="directory_memberships")
    op.drop_index("ix_dir_memberships_identity_id", table_name="directory_memberships")
    op.drop_index("ix_dir_memberships_organization_id", table_name="directory_memberships")
    op.drop_table("directory_memberships")

    op.drop_index("ux_dir_groups_org_connector_external", table_name="directory_groups")
    op.drop_index("ix_dir_groups_organization_id", table_name="directory_groups")
    op.drop_table("directory_groups")

    op.drop_index("ux_dir_identities_org_connector_external", table_name="directory_identities")
    op.drop_index("ix_dir_identities_org_privilege", table_name="directory_identities")
    op.drop_index("ix_dir_identities_organization_id", table_name="directory_identities")
    op.drop_table("directory_identities")
