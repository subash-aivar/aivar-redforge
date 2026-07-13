"""MFA, privileged assurance, and provider tenant ownership — M2.

Adds:
  - mfa_factors: TOTP factor lifecycle (PENDING_ENROLLMENT / ACTIVE /
    REVOKED). secret_ciphertext is Fernet-encrypted at rest
    (Settings.mfa_encryption_key) — plaintext is never persisted.
  - platform_privileged_assurances: short-lived step-up records. The
    opaque token handed to clients IS this row's id; validity is a live
    expires_at/revoked_at lookup, not a cryptographic claim.

Provider tenant ownership:
  - `providers` is a JSON document-store table (migration 0004) with no
    relational columns to ALTER — organization_id is added to each row's
    JSON blob at the application layer (ProviderService), not via a
    schema migration, since the store has no typed columns to add it to.
    Pre-M2 rows have no organization_id key in their JSON blob at all;
    ProviderService.list_providers/get_by_id treat a missing/None
    organization_id as "unowned by any tenant" and exclude/404 it from
    every tenant-scoped call — see ProviderService's module docstring
    for the full reconciliation-gap rationale. No DDL change is needed
    or made here for that reason.

Revision ID: 0012
"""

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision: str = "0011"
branch_labels: None = None
depends_on: None = None


def upgrade() -> None:
    op.create_table(
        "mfa_factors",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("user_id", sa.String(26), nullable=False),
        sa.Column("factor_type", sa.String(20), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("secret_ciphertext", sa.Text, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(26), nullable=True),
    )
    op.create_index("ix_mfa_factors_user_id", "mfa_factors", ["user_id"])
    # A user may hold at most one ACTIVE factor and at most one
    # PENDING_ENROLLMENT factor at a time (application-enforced today via
    # MFAService's pre-check; this partial unique index is the DB-level
    # backstop against a concurrent double-enrollment race).
    op.create_index(
        "ux_mfa_factors_user_status_active",
        "mfa_factors",
        ["user_id", "status"],
        unique=True,
        postgresql_where=sa.text("status = 'active'"),
    )
    op.create_index(
        "ux_mfa_factors_user_status_pending",
        "mfa_factors",
        ["user_id", "status"],
        unique=True,
        postgresql_where=sa.text("status = 'pending_enrollment'"),
    )

    op.create_table(
        "platform_privileged_assurances",
        sa.Column("id", sa.String(43), primary_key=True, nullable=False),
        sa.Column("user_id", sa.String(26), nullable=False),
        sa.Column("established_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_platform_privileged_assurances_user_id",
        "platform_privileged_assurances",
        ["user_id"],
    )
    op.create_index(
        "ix_platform_privileged_assurances_expires_at",
        "platform_privileged_assurances",
        ["expires_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_platform_privileged_assurances_expires_at",
        table_name="platform_privileged_assurances",
    )
    op.drop_index(
        "ix_platform_privileged_assurances_user_id",
        table_name="platform_privileged_assurances",
    )
    op.drop_table("platform_privileged_assurances")

    op.drop_index("ux_mfa_factors_user_status_pending", table_name="mfa_factors")
    op.drop_index("ux_mfa_factors_user_status_active", table_name="mfa_factors")
    op.drop_index("ix_mfa_factors_user_id", table_name="mfa_factors")
    op.drop_table("mfa_factors")
