"""Platform Identity & Super Admin bootstrap — M1.

Adds:
  - platform_assignments: persisted, auditable platform-role grants,
    independent of organization membership. A partial unique index
    guarantees a user can never hold two simultaneously ACTIVE
    assignments of the same role (idempotent-grant safety net; multiple
    *different* users may each hold an active SUPER_ADMIN assignment).
  - platform_bootstrap_state: a singleton row used to atomically claim
    the one-time initial Super Admin bootstrap. The application layer
    performs `UPDATE ... WHERE consumed_at IS NULL RETURNING id` inside
    a transaction — Postgres row-locking makes this race-safe under
    concurrent bootstrap attempts (see PlatformAccessService).
  - platform_audit_log: append-only (by repository convention, not a
    DB-enforced immutable ledger) audit trail for platform privilege
    changes — bootstrap, grant, revoke, and denied privileged actions.

Revision ID: 0011
"""

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str = "0010"
branch_labels: None = None
depends_on: None = None


def upgrade() -> None:
    op.create_table(
        "platform_assignments",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("user_id", sa.String(26), nullable=False),
        sa.Column("role", sa.String(50), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("granted_by", sa.String(26), nullable=False),
        sa.Column("granted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_by", sa.String(26), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("version", sa.Integer, nullable=False, server_default="1"),
    )
    op.create_index(
        "ix_platform_assignments_user_id", "platform_assignments", ["user_id"],
    )
    op.create_index(
        "ix_platform_assignments_role_status",
        "platform_assignments",
        ["role", "status"],
    )
    # Idempotency safety net: a user cannot hold two simultaneously ACTIVE
    # assignments of the same role. Does NOT limit how many different
    # users may hold an active SUPER_ADMIN assignment — last-Super-Admin
    # protection is enforced transactionally in the application layer via
    # SELECT ... FOR UPDATE, not by this constraint.
    op.create_index(
        "ux_platform_assignments_user_role_active",
        "platform_assignments",
        ["user_id", "role"],
        unique=True,
        postgresql_where=sa.text("status = 'active'"),
    )

    op.create_table(
        "platform_bootstrap_state",
        sa.Column("id", sa.String(20), primary_key=True, nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consumed_by", sa.String(26), nullable=True),
    )
    op.execute(
        "INSERT INTO platform_bootstrap_state (id, consumed_at, consumed_by) "
        "VALUES ('singleton', NULL, NULL)"
    )

    op.create_table(
        "platform_audit_log",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("actor_id", sa.String(26), nullable=False),
        sa.Column("target_id", sa.String(26), nullable=False),
        sa.Column("role", sa.String(50), nullable=True),
        sa.Column("outcome", sa.String(20), nullable=False),
        sa.Column("correlation_id", sa.String(64), nullable=False, server_default=""),
        sa.Column("metadata_json", sa.Text, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_platform_audit_log_action", "platform_audit_log", ["action"],
    )
    op.create_index(
        "ix_platform_audit_log_actor_id", "platform_audit_log", ["actor_id"],
    )
    op.create_index(
        "ix_platform_audit_log_created_at", "platform_audit_log", ["created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_platform_audit_log_created_at", table_name="platform_audit_log")
    op.drop_index("ix_platform_audit_log_actor_id", table_name="platform_audit_log")
    op.drop_index("ix_platform_audit_log_action", table_name="platform_audit_log")
    op.drop_table("platform_audit_log")

    op.drop_table("platform_bootstrap_state")

    op.drop_index(
        "ux_platform_assignments_user_role_active", table_name="platform_assignments",
    )
    op.drop_index(
        "ix_platform_assignments_role_status", table_name="platform_assignments",
    )
    op.drop_index("ix_platform_assignments_user_id", table_name="platform_assignments")
    op.drop_table("platform_assignments")
