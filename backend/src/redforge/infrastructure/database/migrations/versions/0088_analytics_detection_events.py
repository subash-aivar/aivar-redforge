"""0088 — M33 Phase 1 analytics event projections.

0088_analytics_detection_events

Migration chain: 0087 → 0088.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0088"
down_revision: str = "0087"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS analytics.detection_events (
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
        "CREATE INDEX IF NOT EXISTS ix_detection_events_tenant_ts "
        "ON analytics.detection_events (tenant_id, event_ts)"
    )
    # COMMENT: Detection domain event projection


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS analytics.detection_events")
