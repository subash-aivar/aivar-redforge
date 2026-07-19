"""0045 — Credential Vault worker schedule state."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0045"
down_revision: str = "0044"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "credential_vault_rotation_policies",
        sa.Column("auto_commit", sa.Boolean(), nullable=False, server_default="true"),
    )
    op.add_column(
        "credential_vault_rotation_policies",
        sa.Column("commit_window_hours", sa.Integer(), nullable=False, server_default="24"),
    )

    op.create_table(
        "credential_vault_rotation_schedule_state",
        sa.Column("credential_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_due_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("claim_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["credential_id"], ["credential_vault_credentials.id"]),
    )
    op.create_index("ix_cv_rss_next_due", "credential_vault_rotation_schedule_state", ["next_due_at"])

    op.create_table(
        "credential_vault_expiration_schedule_state",
        sa.Column("credential_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("last_scanned_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("policy_expiry_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_scan_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("claim_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["credential_id"], ["credential_vault_credentials.id"]),
    )
    op.create_index(
        "ix_cv_ess_next_scan", "credential_vault_expiration_schedule_state", ["next_scan_at"]
    )

    op.create_table(
        "credential_vault_dek_rewrap_progress",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("version_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("old_master_key_id", sa.String(256), nullable=False),
        sa.Column("new_master_key_id", sa.String(256), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("rewrapped_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("credential_vault_dek_rewrap_progress")
    op.drop_table("credential_vault_expiration_schedule_state")
    op.drop_table("credential_vault_rotation_schedule_state")
    op.drop_column("credential_vault_rotation_policies", "commit_window_hours")
    op.drop_column("credential_vault_rotation_policies", "auto_commit")
