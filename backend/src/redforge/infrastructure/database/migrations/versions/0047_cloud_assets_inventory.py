"""0047 — M26 Cloud Asset inventory (cloud_assets)."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0047"
down_revision: str = "0046"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_SCHEMA = "cloud_security"


def upgrade() -> None:
    op.create_table(
        "cloud_assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("cloud_account_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", sa.String(length=26), nullable=False),
        sa.Column("asset_type", sa.String(length=64), nullable=False),
        sa.Column("provider_id", sa.String(length=2048), nullable=False),
        sa.Column("region", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("availability_zone", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("display_name", sa.String(length=512), nullable=False),
        sa.Column("provider_metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("normalized_config", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("tags", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("relationships", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("posture_state", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_deleted", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(
            ["cloud_account_id"],
            [f"{_SCHEMA}.cloud_accounts.id"],
            name="fk_cloud_assets_cloud_account_id_cloud_accounts",
        ),
        sa.UniqueConstraint(
            "cloud_account_id",
            "provider_id",
            name="uq_cloud_assets_account_provider",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cloud_assets_organization_id",
        "cloud_assets",
        ["organization_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cloud_assets_cloud_account_id",
        "cloud_assets",
        ["cloud_account_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cloud_assets_asset_type",
        "cloud_assets",
        ["asset_type"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cloud_assets_org_asset_type",
        "cloud_assets",
        ["organization_id", "asset_type"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cloud_assets_account_asset_type",
        "cloud_assets",
        ["cloud_account_id", "asset_type"],
        schema=_SCHEMA,
    )
    op.execute(
        sa.text(
            f"CREATE INDEX ix_cloud_assets_tags_gin ON {_SCHEMA}.cloud_assets "
            "USING GIN (tags)"
        )
    )


def downgrade() -> None:
    op.execute(sa.text(f"DROP INDEX IF EXISTS {_SCHEMA}.ix_cloud_assets_tags_gin"))
    op.drop_index("ix_cloud_assets_account_asset_type", table_name="cloud_assets", schema=_SCHEMA)
    op.drop_index("ix_cloud_assets_org_asset_type", table_name="cloud_assets", schema=_SCHEMA)
    op.drop_index("ix_cloud_assets_asset_type", table_name="cloud_assets", schema=_SCHEMA)
    op.drop_index("ix_cloud_assets_cloud_account_id", table_name="cloud_assets", schema=_SCHEMA)
    op.drop_index("ix_cloud_assets_organization_id", table_name="cloud_assets", schema=_SCHEMA)
    op.drop_table("cloud_assets", schema=_SCHEMA)
