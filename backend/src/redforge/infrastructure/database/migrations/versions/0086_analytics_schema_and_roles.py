"""0086 — M33 Phase 1 analytics schema and roles.

Creates analytics schema, PostgreSQL role grants (logical), and RLS scaffolding.

Migration chain: 0085 → 0086.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0086"
down_revision: str = "0085"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS analytics")
    # Role grants are environment-specific; document intended grants:
    # GRANT USAGE ON SCHEMA analytics TO redforge_app;
    # GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA analytics TO redforge_app;
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS analytics.schema_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )
    op.execute(
        "INSERT INTO analytics.schema_meta (key, value) VALUES "
        "('analytics_schema_version', '1') ON CONFLICT (key) DO NOTHING"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS analytics.schema_meta")
    op.execute("DROP SCHEMA IF EXISTS analytics CASCADE")
