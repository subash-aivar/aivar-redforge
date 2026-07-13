"""Enterprise Identity, Super Admin & RBAC Control Plane — M17.

Platform Super Admin authority (platform_assignments/platform_bootstrap_
state/platform_audit_log, migration 0011) is REUSED UNCHANGED — this
milestone adds no platform-authority tables at all. This migration adds
only the genuinely missing piece per repository truth: organization-
scoped custom Roles and Groups, layered on top of the pre-existing fixed
MembershipRole/Permission/ROLE_PERMISSIONS system (unchanged).

Adds:
  - organization_roles: admin-defined, organization-owned roles. A
    `(id, organization_id)` unique constraint exists specifically so
    downstream tables can composite-FK against it — the same pattern
    M16's network_state_snapshots used against network_monitoring_
    policies — making a cross-tenant role reference a foreign-key
    violation, not just an application-layer bug.
  - organization_role_permissions: one row per (role, permission).
    `permission` is a plain string column but is ALWAYS validated
    against `Permission` (domain.identity.value_objects) before a row is
    ever written — there is no path for a `PlatformPermission` value or
    an arbitrary string to land here (see application/rbac/role_service.py).
  - organization_groups: admin-defined, organization-owned security
    groups. Same `(id, organization_id)` composite-unique pattern.
  - organization_group_memberships: user<->group join. Composite FK to
    organization_groups(id, organization_id) makes cross-tenant group
    membership a database-level impossibility, not just an
    application check.
  - organization_group_roles: group<->role join. Composite FK to BOTH
    organization_groups(id, organization_id) and organization_roles(id,
    organization_id) — a group can only ever be assigned a role that
    belongs to the SAME organization, enforced by Postgres itself.
  - organization_user_roles: direct user<->role join (bypassing groups).
    Composite FK to organization_roles(id, organization_id).
  - organization_admin_audit_log: append-only (by repository
    convention) audit trail for M17's organization-scoped administrative
    mutations — role/group create/update/delete, membership/role
    assignment changes. Distinct from platform_audit_log (M1), which
    remains platform-scoped only; this table is always organization_id-
    scoped and is queryable per-tenant.

Revision ID: 0026
"""

import sqlalchemy as sa
from alembic import op

revision: str = "0026"
down_revision: str = "0025"
branch_labels: None = None
depends_on: None = None


def upgrade() -> None:
    op.create_table(
        "organization_roles",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("normalized_name", sa.String(100), nullable=False),
        sa.Column("description", sa.String(500), nullable=False, server_default=""),
        sa.Column("is_system", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("id", "organization_id", name="ux_org_roles_id_org"),
        sa.UniqueConstraint(
            "organization_id", "normalized_name", name="ux_org_roles_org_normalized_name"
        ),
    )
    op.create_index("ix_org_roles_organization_id", "organization_roles", ["organization_id"])

    op.create_table(
        "organization_role_permissions",
        sa.Column("role_id", sa.String(26), nullable=False),
        sa.Column("permission", sa.String(100), nullable=False),
        sa.PrimaryKeyConstraint("role_id", "permission", name="pk_org_role_permissions"),
        sa.ForeignKeyConstraint(
            ["role_id"], ["organization_roles.id"],
            name="fk_org_role_permissions_role", ondelete="CASCADE",
        ),
    )

    op.create_table(
        "organization_groups",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("normalized_name", sa.String(100), nullable=False),
        sa.Column("description", sa.String(500), nullable=False, server_default=""),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("id", "organization_id", name="ux_org_groups_id_org"),
        sa.UniqueConstraint(
            "organization_id", "normalized_name", name="ux_org_groups_org_normalized_name"
        ),
    )
    op.create_index("ix_org_groups_organization_id", "organization_groups", ["organization_id"])

    op.create_table(
        "organization_group_memberships",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("group_id", sa.String(26), nullable=False),
        sa.Column("user_id", sa.String(26), nullable=False),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("group_id", "user_id", name="ux_group_memberships_group_user"),
        sa.ForeignKeyConstraint(
            ["group_id", "organization_id"],
            ["organization_groups.id", "organization_groups.organization_id"],
            name="fk_group_memberships_same_tenant_group", ondelete="CASCADE",
        ),
    )
    op.create_index(
        "ix_group_memberships_org_user", "organization_group_memberships",
        ["organization_id", "user_id"],
    )

    op.create_table(
        "organization_group_roles",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("group_id", sa.String(26), nullable=False),
        sa.Column("role_id", sa.String(26), nullable=False),
        sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("group_id", "role_id", name="ux_group_roles_group_role"),
        sa.ForeignKeyConstraint(
            ["group_id", "organization_id"],
            ["organization_groups.id", "organization_groups.organization_id"],
            name="fk_group_roles_same_tenant_group", ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["role_id", "organization_id"],
            ["organization_roles.id", "organization_roles.organization_id"],
            name="fk_group_roles_same_tenant_role", ondelete="CASCADE",
        ),
    )
    op.create_index(
        "ix_group_roles_org_group", "organization_group_roles", ["organization_id", "group_id"],
    )

    op.create_table(
        "organization_user_roles",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("user_id", sa.String(26), nullable=False),
        sa.Column("role_id", sa.String(26), nullable=False),
        sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "organization_id", "user_id", "role_id", name="ux_user_roles_org_user_role"
        ),
        sa.ForeignKeyConstraint(
            ["role_id", "organization_id"],
            ["organization_roles.id", "organization_roles.organization_id"],
            name="fk_user_roles_same_tenant_role", ondelete="CASCADE",
        ),
    )
    op.create_index(
        "ix_user_roles_org_user", "organization_user_roles", ["organization_id", "user_id"],
    )

    op.create_table(
        "organization_admin_audit_log",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("actor_id", sa.String(26), nullable=False),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("target_type", sa.String(50), nullable=False),
        sa.Column("target_id", sa.String(26), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_org_admin_audit_org_occurred", "organization_admin_audit_log",
        ["organization_id", "occurred_at"],
    )


def downgrade() -> None:
    op.drop_table("organization_admin_audit_log")
    op.drop_table("organization_user_roles")
    op.drop_table("organization_group_roles")
    op.drop_table("organization_group_memberships")
    op.drop_table("organization_groups")
    op.drop_table("organization_role_permissions")
    op.drop_table("organization_roles")
