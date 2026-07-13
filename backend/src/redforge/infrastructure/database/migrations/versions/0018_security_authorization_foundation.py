"""Security Authorization & Execution Policy foundation — M10.

Adds the AUTHORIZED PT SCOPE & EXECUTION POLICY control plane:
  - security_authorizations: canonical, tenant-owned authorization
    record. Lifecycle: draft -> pending_approval -> active ->
    revoked/expired, or pending_approval -> rejected. action_classes is
    a JSON array of the closed ActionClass taxonomy (server-validated
    at the application layer, never client-defined strings beyond that
    enum).
  - security_authorization_scope: exact canonical entities
    (ai_target/ai_asset ids) an authorization covers. Tenant integrity
    is DATABASE-enforced via a composite foreign key on
    (authorization_id, organization_id) — the same pattern M4/M5
    established for security_graph_edges / directory_memberships.
  - security_authorization_approvals: one immutable-once-decided
    approval record per authorization (created at submission, decided
    at most once). Tenant-integrity FK to security_authorizations.
  - security_authorization_decisions: immutable audit log of every
    ExecutionPolicyService.evaluate() call (ALLOW, DENY, and
    APPROVAL_REQUIRED alike). authorization_id is nullable and
    deliberately has NO foreign key — a decision that found no
    authorization at all (AUTHORIZATION_NOT_FOUND) must still be
    recorded; "every decision is auditable" cannot depend on an
    authorization existing.

No execution/payload/credential tables are introduced — M10 builds only
the control plane, not any execution capability.

Revision ID: 0018
"""

import sqlalchemy as sa
from alembic import op

revision: str = "0018"
down_revision: str = "0017"
branch_labels: None = None
depends_on: None = None


def upgrade() -> None:
    op.create_table(
        "security_authorizations",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("requester_user_id", sa.String(26), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("action_classes", sa.JSON, nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer, nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "id", "organization_id", name="ux_security_authorizations_id_org",
        ),
    )
    op.create_index(
        "ix_security_authorizations_org_status",
        "security_authorizations", ["organization_id", "status"],
    )
    op.create_index(
        "ix_security_authorizations_org_valid_until",
        "security_authorizations", ["organization_id", "valid_until"],
    )
    op.create_index(
        "ix_security_authorizations_org_requester",
        "security_authorizations", ["organization_id", "requester_user_id"],
    )

    op.create_table(
        "security_authorization_scope",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("authorization_id", sa.String(26), nullable=False),
        sa.Column("entity_type", sa.String(20), nullable=False),
        sa.Column("entity_id", sa.String(64), nullable=False),
        sa.ForeignKeyConstraint(
            ["authorization_id", "organization_id"],
            ["security_authorizations.id", "security_authorizations.organization_id"],
            name="fk_authorization_scope_same_tenant",
        ),
        sa.UniqueConstraint(
            "authorization_id", "entity_type", "entity_id",
            name="ux_authorization_scope_entry",
        ),
    )
    op.create_index(
        "ix_authorization_scope_org", "security_authorization_scope", ["organization_id"],
    )
    op.create_index(
        "ix_authorization_scope_authorization_id",
        "security_authorization_scope", ["authorization_id"],
    )
    op.create_index(
        "ix_authorization_scope_org_entity",
        "security_authorization_scope", ["organization_id", "entity_type", "entity_id"],
    )

    op.create_table(
        "security_authorization_approvals",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("authorization_id", sa.String(26), nullable=False),
        sa.Column("requester_user_id", sa.String(26), nullable=False),
        sa.Column("approver_user_id", sa.String(26), nullable=True),
        sa.Column("decision", sa.String(20), nullable=True),
        sa.Column("reason", sa.String(500), nullable=False, server_default=""),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["authorization_id", "organization_id"],
            ["security_authorizations.id", "security_authorizations.organization_id"],
            name="fk_authorization_approval_same_tenant",
        ),
    )
    op.create_index(
        "ix_authorization_approvals_org",
        "security_authorization_approvals", ["organization_id"],
    )
    op.create_index(
        "ix_authorization_approvals_authorization_id",
        "security_authorization_approvals", ["authorization_id"],
    )

    op.create_table(
        "security_authorization_decisions",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("actor_user_id", sa.String(26), nullable=False),
        sa.Column("authorization_id", sa.String(26), nullable=True),
        sa.Column("action_class", sa.String(30), nullable=True),
        sa.Column("raw_action_class", sa.String(100), nullable=False),
        sa.Column("entity_refs", sa.JSON, nullable=False),
        sa.Column("decision", sa.String(20), nullable=False),
        sa.Column("reason_code", sa.String(40), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_authorization_decisions_org_time",
        "security_authorization_decisions", ["organization_id", "evaluated_at"],
    )
    op.create_index(
        "ix_authorization_decisions_org_authorization",
        "security_authorization_decisions", ["organization_id", "authorization_id"],
    )
    op.create_index(
        "ix_authorization_decisions_org_decision",
        "security_authorization_decisions", ["organization_id", "decision"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_authorization_decisions_org_decision", table_name="security_authorization_decisions",
    )
    op.drop_index(
        "ix_authorization_decisions_org_authorization",
        table_name="security_authorization_decisions",
    )
    op.drop_index(
        "ix_authorization_decisions_org_time", table_name="security_authorization_decisions",
    )
    op.drop_table("security_authorization_decisions")

    op.drop_index(
        "ix_authorization_approvals_authorization_id",
        table_name="security_authorization_approvals",
    )
    op.drop_index(
        "ix_authorization_approvals_org", table_name="security_authorization_approvals",
    )
    op.drop_table("security_authorization_approvals")

    op.drop_index("ix_authorization_scope_org_entity", table_name="security_authorization_scope")
    op.drop_index(
        "ix_authorization_scope_authorization_id", table_name="security_authorization_scope",
    )
    op.drop_index("ix_authorization_scope_org", table_name="security_authorization_scope")
    op.drop_table("security_authorization_scope")

    op.drop_index(
        "ix_security_authorizations_org_requester", table_name="security_authorizations",
    )
    op.drop_index(
        "ix_security_authorizations_org_valid_until", table_name="security_authorizations",
    )
    op.drop_index("ix_security_authorizations_org_status", table_name="security_authorizations")
    op.drop_table("security_authorizations")
