"""0155 — Phase 2C: discovery pagination/checkpointing + DB performance.

Migration chain: 0154 -> 0155.

Adds:
- sync_runs.cursor / sync_runs.pages_processed — persisted checkpoint
  state so a paginated discovery run can resume after a crash/restart
  instead of restarting from zero (P0-1).
- GIN index on discovered_assets.tags — the tag filter in
  find_all_for_tenant used to be a Python-side loop after fetching every
  row from the DB; it is now pushed into SQL via the JSONB `?` (has_key)
  operator, which this index supports (P0-3).
- Index on asset_relationships.target_asset_id — only source_asset_id
  and tenant_id were indexed before, making any reverse-direction
  relationship lookup a sequential scan (P0-3).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0155"
down_revision: str = "0154"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "sync_runs",
        sa.Column("cursor", sa.Text(), nullable=True),
        schema="integration_hub",
    )
    op.add_column(
        "sync_runs",
        sa.Column(
            "pages_processed", sa.Integer(), nullable=False, server_default="0"
        ),
        schema="integration_hub",
    )

    op.create_index(
        "ix_discovered_assets_tags_gin",
        "discovered_assets",
        ["tags"],
        schema="integration_hub",
        postgresql_using="gin",
    )

    op.create_index(
        "ix_asset_relationships_target",
        "asset_relationships",
        ["target_asset_id"],
        schema="integration_hub",
    )


def downgrade() -> None:
    op.drop_index(
        "ix_asset_relationships_target",
        table_name="asset_relationships",
        schema="integration_hub",
    )
    op.drop_index(
        "ix_discovered_assets_tags_gin",
        table_name="discovered_assets",
        schema="integration_hub",
    )
    op.drop_column("sync_runs", "pages_processed", schema="integration_hub")
    op.drop_column("sync_runs", "cursor", schema="integration_hub")
