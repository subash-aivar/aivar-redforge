"""0089 — M33 Phase 1 analytics event projections.

0089_analytics_execution_campaign_events

Migration chain: 0088 → 0089.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0089"
down_revision: str = "0088"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS analytics.execution_events (
            event_id TEXT NOT NULL,
            tenant_id UUID NOT NULL,
            event_type TEXT NOT NULL,
            event_ts TIMESTAMPTZ NOT NULL,
            payload JSONB NOT NULL DEFAULT '{}'::jsonb,
            ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            archived BOOLEAN NOT NULL DEFAULT FALSE,
            PRIMARY KEY (tenant_id, event_id)
        )
        """
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_execution_events_tenant_ts "
        "ON analytics.execution_events (tenant_id, event_ts)"
    )
    # COMMENT: Red-team execution event projection

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS analytics.campaign_events (
            event_id TEXT NOT NULL,
            tenant_id UUID NOT NULL,
            event_type TEXT NOT NULL,
            event_ts TIMESTAMPTZ NOT NULL,
            payload JSONB NOT NULL DEFAULT '{}'::jsonb,
            ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            archived BOOLEAN NOT NULL DEFAULT FALSE,
            PRIMARY KEY (tenant_id, event_id)
        )
        """
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_campaign_events_tenant_ts "
        "ON analytics.campaign_events (tenant_id, event_ts)"
    )
    # COMMENT: Campaign event projection


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS analytics.execution_events")
    op.execute("DROP TABLE IF EXISTS analytics.campaign_events")
