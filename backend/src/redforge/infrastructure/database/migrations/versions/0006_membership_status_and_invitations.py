"""Replace memberships.is_active with a 3-state status column, and
create the invitations table.

Membership needed a richer lifecycle than a boolean: SUSPENDED
(temporary, reversible) is a distinct state from REMOVED (terminal) —
the Enterprise Identity Platform sprint's suspend/reactivate/remove
member operations cannot be expressed correctly with a single boolean.
Existing `is_active=true` rows map to 'active'; `is_active=false` rows
(there should be none pre-Alpha, but handled defensively) map to
'removed' since that was the only meaning the old boolean's False value
ever carried.

invitations is a new table, real indexed columns for the same reason
memberships is: the token-hash lookup on acceptance is a hot-path,
security-critical equality query.

Revision ID: 0006
Revises: 0005
Create Date: 2026-07-08 00:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "memberships",
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
    )
    op.execute(
        "UPDATE memberships SET status = CASE WHEN is_active THEN 'active' "
        "ELSE 'removed' END"
    )
    op.drop_column("memberships", "is_active")

    op.create_table(
        "invitations",
        sa.Column("id", sa.String(26), nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("email", sa.String(254), nullable=False),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("invited_by_user_id", sa.String(26), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accepted_by_user_id", sa.String(26), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_invitations"),
        sa.UniqueConstraint("token_hash", name="uq_invitation_token_hash"),
    )
    op.create_index("ix_invitations_organization_id", "invitations", ["organization_id"])
    op.create_index("ix_invitations_email", "invitations", ["email"])
    op.create_index("ix_invitations_token_hash", "invitations", ["token_hash"])
    # Partial-style lookup index for the duplicate-pending-invitation
    # check (organization_id, email, status) — Postgres will use this
    # for the common "any PENDING invitation for this org+email?" query.
    op.create_index(
        "ix_invitations_org_email_status",
        "invitations",
        ["organization_id", "email", "status"],
    )


def downgrade() -> None:
    op.drop_index("ix_invitations_org_email_status", table_name="invitations")
    op.drop_index("ix_invitations_token_hash", table_name="invitations")
    op.drop_index("ix_invitations_email", table_name="invitations")
    op.drop_index("ix_invitations_organization_id", table_name="invitations")
    op.drop_table("invitations")

    op.add_column(
        "memberships",
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
    )
    op.execute(
        "UPDATE memberships SET is_active = (status = 'active')"
    )
    op.drop_column("memberships", "status")
