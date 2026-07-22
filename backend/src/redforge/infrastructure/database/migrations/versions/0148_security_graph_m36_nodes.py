"""0148 — M36 migration.

Migration chain: 0147 → 0148.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0148"
down_revision: str = "0147"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = 'security_graph' AND table_name = 'node_types'
            ) THEN
                INSERT INTO security_graph.node_types(node_type)
                VALUES ('intelligence_suggestion'), ('optimization_model'), ('threat_hunt_candidate')
                ON CONFLICT DO NOTHING;
            END IF;
            IF EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = 'security_graph' AND table_name = 'edge_types'
            ) THEN
                INSERT INTO security_graph.edge_types(edge_type)
                VALUES ('suggested_modification'), ('approved_suggestion'),
                       ('outcome_feedback'), ('generated_detection')
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
                WHERE node_type IN ('intelligence_suggestion', 'optimization_model', 'threat_hunt_candidate');
            END IF;
            IF EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = 'security_graph' AND table_name = 'edge_types'
            ) THEN
                DELETE FROM security_graph.edge_types
                WHERE edge_type IN ('suggested_modification', 'approved_suggestion',
                                    'outcome_feedback', 'generated_detection');
            END IF;
        END $$;
        """
    )
