"""0046 — M26 Cloud Security foundation (cloud_providers, cloud_accounts)."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0046"
down_revision: str = "0045"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_SCHEMA = "cloud_security"


def upgrade() -> None:
    op.execute(sa.text(f"CREATE SCHEMA IF NOT EXISTS {_SCHEMA}"))

    op.create_table(
        "cloud_providers",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", sa.String(length=26), nullable=False),
        sa.Column("provider_type", sa.String(length=16), nullable=False),
        sa.Column("display_name", sa.String(length=256), nullable=False),
        sa.Column("discovery_config", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "organization_id",
            "provider_type",
            name="uq_cloud_providers_org_type",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cloud_providers_organization_id",
        "cloud_providers",
        ["organization_id"],
        schema=_SCHEMA,
    )

    op.create_table(
        "cloud_accounts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("cloud_provider_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", sa.String(length=26), nullable=False),
        sa.Column("external_id", sa.String(length=256), nullable=False),
        sa.Column("display_name", sa.String(length=256), nullable=False),
        sa.Column("account_type", sa.String(length=32), nullable=False),
        sa.Column("regions", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("credential_ref", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("sync_state", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("tags", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(
            ["cloud_provider_id"],
            [f"{_SCHEMA}.cloud_providers.id"],
            name="fk_cloud_accounts_cloud_provider_id_cloud_providers",
        ),
        sa.UniqueConstraint(
            "cloud_provider_id",
            "external_id",
            name="uq_cloud_accounts_provider_external",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cloud_accounts_organization_id",
        "cloud_accounts",
        ["organization_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cloud_accounts_cloud_provider_id",
        "cloud_accounts",
        ["cloud_provider_id"],
        schema=_SCHEMA,
    )


def downgrade() -> None:
    op.drop_table("cloud_accounts", schema=_SCHEMA)
    op.drop_table("cloud_providers", schema=_SCHEMA)
    op.execute(sa.text(f"DROP SCHEMA IF EXISTS {_SCHEMA}"))
