"""0102 — M34 Phase 1 analytics.incident_events (MTTR pipeline).

Migration chain: 0101 → 0102.
Creates partitioned incident_events in the M33-owned analytics schema.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0102"
down_revision: str = "0101"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE analytics.incident_events (
            event_id        UUID          NOT NULL,
            tenant_id       UUID          NOT NULL,
            incident_id     UUID          NOT NULL,
            event_type      VARCHAR(100)  NOT NULL,
            severity        VARCHAR(50),
            classified_at   TIMESTAMPTZ,
            closed_at       TIMESTAMPTZ,
            resolution_type VARCHAR(50),
            event_ts        TIMESTAMPTZ   NOT NULL,
            payload         JSONB         NOT NULL,
            ingested_at     TIMESTAMPTZ   NOT NULL DEFAULT now(),
            PRIMARY KEY (tenant_id, event_id)
        ) PARTITION BY HASH (tenant_id)
        """
    )
    for rem in range(8):
        op.execute(
            f"""
            CREATE TABLE analytics.incident_events_p{rem}
            PARTITION OF analytics.incident_events
            FOR VALUES WITH (MODULUS 8, REMAINDER {rem})
            """
        )
    op.execute(
        "CREATE INDEX ix_incident_events_tenant_id "
        "ON analytics.incident_events(tenant_id)"
    )
    op.execute(
        "CREATE INDEX ix_incident_events_classified_at "
        "ON analytics.incident_events(tenant_id, classified_at) "
        "WHERE event_type = 'incident_classified'"
    )
    op.execute(
        "CREATE INDEX ix_incident_events_closed_at "
        "ON analytics.incident_events(tenant_id, closed_at) "
        "WHERE event_type = 'incident_closed'"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS analytics.incident_events CASCADE")
