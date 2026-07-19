"""0044 — Credential Vault foundation tables."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0044"
down_revision: str = "0043"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "credential_vault_vault_backends",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("backend_type", sa.String(64), nullable=False),
        sa.Column("is_default", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("config_encrypted", sa.LargeBinary(), nullable=False),
        sa.Column("config_key_envelope", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint("tenant_id", "name", name="uq_cvvb_tenant_name"),
    )
    op.create_index("ix_cvvb_tenant", "credential_vault_vault_backends", ["tenant_id"])

    op.create_table(
        "credential_vault_rotation_policies",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("interval_days", sa.Integer(), nullable=True),
        sa.Column("max_versions_kept", sa.Integer(), nullable=False),
        sa.Column("notify_days_before", sa.Integer(), nullable=False),
        sa.Column("auto_rotate", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint("tenant_id", "name", name="uq_cv_rotation_policies_tenant_name"),
    )
    op.create_index("ix_cv_rotation_policies_tenant", "credential_vault_rotation_policies", ["tenant_id"])

    op.create_table(
        "credential_vault_expiration_policies",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("ttl_days", sa.Integer(), nullable=False),
        sa.Column("warn_days_before", sa.Integer(), nullable=False),
        sa.Column("hard_expire", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint("tenant_id", "name", name="uq_cv_expiration_policies_tenant_name"),
    )
    op.create_index("ix_cv_expiration_policies_tenant", "credential_vault_expiration_policies", ["tenant_id"])

    op.create_table(
        "credential_vault_credentials",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("cred_category", sa.String(64), nullable=False),
        sa.Column("cred_subtype", sa.String(64), nullable=False),
        sa.Column("schema_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("owner_principal_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("active_version_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("rotation_policy_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("expiration_policy_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("vault_backend_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("tags_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(["vault_backend_id"], ["credential_vault_vault_backends.id"]),
        sa.ForeignKeyConstraint(["rotation_policy_id"], ["credential_vault_rotation_policies.id"]),
        sa.ForeignKeyConstraint(["expiration_policy_id"], ["credential_vault_expiration_policies.id"]),
        sa.UniqueConstraint("tenant_id", "name", name="uq_credential_vault_credentials_tenant_name"),
    )
    op.create_index("ix_cv_credentials_tenant_state", "credential_vault_credentials", ["tenant_id", "state"])
    op.create_index("ix_cv_credentials_rotation_policy", "credential_vault_credentials", ["tenant_id", "rotation_policy_id"])
    op.create_index("ix_cv_credentials_expiration_policy", "credential_vault_credentials", ["tenant_id", "expiration_policy_id"])
    op.create_index("ix_credential_vault_credentials_tenant_id", "credential_vault_credentials", ["tenant_id"])

    op.create_table(
        "credential_vault_versions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("credential_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column("version_state", sa.String(32), nullable=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("cipher_algorithm", sa.String(64), nullable=False),
        sa.Column("iv", sa.LargeBinary(), nullable=False),
        sa.Column("tag", sa.LargeBinary(), nullable=False),
        sa.Column("payload_size", sa.Integer(), nullable=False),
        sa.Column("wrapped_dek", sa.LargeBinary(), nullable=False),
        sa.Column("master_key_id", sa.String(256), nullable=False),
        sa.Column("wrapping_algorithm", sa.String(64), nullable=False),
        sa.Column("key_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("rotation_trigger", sa.String(64), nullable=True),
        sa.Column("rotation_prev_version_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("rotation_policy_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("rotation_notes", sa.Text(), nullable=True),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(["credential_id"], ["credential_vault_credentials.id"]),
    )
    op.create_index("ix_cv_versions_cred_state", "credential_vault_versions", ["credential_id", "tenant_id", "version_state"])
    op.create_index("ix_cv_versions_cred_number", "credential_vault_versions", ["credential_id", "tenant_id", "version_number"])
    op.create_index("ix_credential_vault_versions_credential_id", "credential_vault_versions", ["credential_id"])

    op.create_foreign_key(
        "fk_cv_credentials_active_version",
        "credential_vault_credentials",
        "credential_vault_versions",
        ["active_version_id"],
        ["id"],
        deferrable=True,
        initially="DEFERRED",
    )

    op.create_table(
        "credential_vault_audit_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("credential_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["credential_id"], ["credential_vault_credentials.id"]),
        sa.UniqueConstraint("credential_id", name="uq_cv_audit_logs_credential_id"),
    )

    op.create_table(
        "credential_vault_audit_entries",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("audit_log_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("credential_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("operation", sa.String(64), nullable=False),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("principal_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("client_ip", sa.String(45), nullable=True),
        sa.Column("request_id", sa.String(128), nullable=True),
        sa.Column("version_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("state_before", sa.String(32), nullable=True),
        sa.Column("state_after", sa.String(32), nullable=True),
        sa.ForeignKeyConstraint(["audit_log_id"], ["credential_vault_audit_logs.id"]),
    )
    op.create_index("ix_cv_audit_entries_log_occurred", "credential_vault_audit_entries", ["audit_log_id", "occurred_at"])
    op.create_index("ix_cv_audit_entries_cred_tenant", "credential_vault_audit_entries", ["credential_id", "tenant_id"])
    op.create_index("ix_credential_vault_audit_entries_audit_log_id", "credential_vault_audit_entries", ["audit_log_id"])

    op.create_table(
        "credential_vault_approval_requests",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("credential_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("operation", sa.String(64), nullable=False),
        sa.Column("requester_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("approver_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_cv_approval_requests_lookup",
        "credential_vault_approval_requests",
        ["credential_id", "tenant_id", "operation"],
    )


def downgrade() -> None:
    op.drop_table("credential_vault_approval_requests")
    op.drop_table("credential_vault_audit_entries")
    op.drop_table("credential_vault_audit_logs")
    op.drop_constraint("fk_cv_credentials_active_version", "credential_vault_credentials", type_="foreignkey")
    op.drop_table("credential_vault_versions")
    op.drop_table("credential_vault_credentials")
    op.drop_table("credential_vault_expiration_policies")
    op.drop_table("credential_vault_rotation_policies")
    op.drop_table("credential_vault_vault_backends")
