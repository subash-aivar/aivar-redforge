"""0129 — M35 migration.

Migration chain: 0128 → 0129.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0129"
down_revision: str = "0128"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    # Extend graph enums via lookup tables when present; otherwise no-op safe inserts.
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = 'security_graph' AND table_name = 'node_types'
            ) THEN
                INSERT INTO security_graph.node_types(node_type)
                VALUES ('playbook'), ('automated_action')
                ON CONFLICT DO NOTHING;
            END IF;
            IF EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = 'security_graph' AND table_name = 'edge_types'
            ) THEN
                INSERT INTO security_graph.edge_types(edge_type)
                VALUES ('triggered_playbook'), ('executed_action'), ('action_on_asset'), ('rolled_back_by')
                ON CONFLICT DO NOTHING;
            END IF;
        END $$;
        """
    )


def downgrade() -> None:

    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = 'security_graph' AND table_name = 'node_types'
            ) THEN
                DELETE FROM security_graph.node_types
                WHERE node_type IN ('playbook', 'automated_action');
            END IF;
            IF EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = 'security_graph' AND table_name = 'edge_types'
            ) THEN
                DELETE FROM security_graph.edge_types
                WHERE edge_type IN ('triggered_playbook', 'executed_action', 'action_on_asset', 'rolled_back_by');
            END IF;
        END $$;
        """
    )
