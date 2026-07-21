"""0090 — M33 Phase 1 analytics event projections.

0090_analytics_exposure_ai_posture_events

Migration chain: 0089 → 0090.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0090"
down_revision: str = "0089"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS analytics.exposure_events (
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
        "CREATE INDEX IF NOT EXISTS ix_exposure_events_tenant_ts "
        "ON analytics.exposure_events (tenant_id, event_ts)"
    )
    # COMMENT: Exposure event projection

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS analytics.ai_posture_events (
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
        "CREATE INDEX IF NOT EXISTS ix_ai_posture_events_tenant_ts "
        "ON analytics.ai_posture_events (tenant_id, event_ts)"
    )
    # COMMENT: AI posture event projection


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS analytics.exposure_events")
    op.execute("DROP TABLE IF EXISTS analytics.ai_posture_events")
