"""0048 — M26 Cloud IAM principals (CIEM foundation)."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0048"
down_revision: str = "0047"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_SCHEMA = "cloud_security"


def upgrade() -> None:
    op.create_table(
        "cloud_iam_principals",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("cloud_account_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", sa.String(length=26), nullable=False),
        sa.Column("principal_type", sa.String(length=64), nullable=False),
        sa.Column("provider_id", sa.String(length=2048), nullable=False),
        sa.Column("display_name", sa.String(length=512), nullable=False),
        sa.Column("attached_policies", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("trust_relationships", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("privilege_level", sa.String(length=32), nullable=False, server_default="NONE"),
        sa.Column("is_federated", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("is_human", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("last_activity_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("risk_indicators", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("is_disabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("is_deleted", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(
            ["cloud_account_id"],
            [f"{_SCHEMA}.cloud_accounts.id"],
            name="fk_cloud_iam_principals_cloud_account_id_cloud_accounts",
        ),
        sa.UniqueConstraint(
            "cloud_account_id",
            "provider_id",
            name="uq_cloud_iam_principals_account_provider",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cloud_iam_principals_organization_id",
        "cloud_iam_principals",
        ["organization_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cloud_iam_principals_cloud_account_id",
        "cloud_iam_principals",
        ["cloud_account_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cloud_iam_principals_principal_type",
        "cloud_iam_principals",
        ["principal_type"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cloud_iam_principals_account_type",
        "cloud_iam_principals",
        ["cloud_account_id", "principal_type"],
        schema=_SCHEMA,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_cloud_iam_principals_account_type",
        table_name="cloud_iam_principals",
        schema=_SCHEMA,
    )
    op.drop_index(
        "ix_cloud_iam_principals_principal_type",
        table_name="cloud_iam_principals",
        schema=_SCHEMA,
    )
    op.drop_index(
        "ix_cloud_iam_principals_cloud_account_id",
        table_name="cloud_iam_principals",
        schema=_SCHEMA,
    )
    op.drop_index(
        "ix_cloud_iam_principals_organization_id",
        table_name="cloud_iam_principals",
        schema=_SCHEMA,
    )
    op.drop_table("cloud_iam_principals", schema=_SCHEMA)
