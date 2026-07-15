"""DDoS active-incident uniqueness constraint — M19 P0 fix.

Adds a partial unique index that enforces at-most-one active/open incident
per (organization_id, resource_id) pair while an incident is in an open
lifecycle state.

This is the database-level invariant that makes open_or_update_incident()
safe across multiple application replicas, detector workers, and retries.
The existing SAVEPOINT + IntegrityError refetch pattern in the repository
now has a constraint to trigger against.

Open states: DETECTED, ACTIVE, ESCALATED, MITIGATING, MONITORING
Closed states (not covered): RESOLVED, CLOSED — multiple historical
incidents for the same resource are permitted.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0032"
down_revision: str = "0031"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_OPEN_STATES = "('DETECTED', 'ACTIVE', 'ESCALATED', 'MITIGATING', 'MONITORING')"

_INDEX_NAME = "uix_di_one_active_per_resource"


def upgrade() -> None:
    op.execute(
        f"""
        CREATE UNIQUE INDEX {_INDEX_NAME}
        ON ddos_incidents (organization_id, resource_id)
        WHERE status IN {_OPEN_STATES}
        """
    )


def downgrade() -> None:
    op.execute(f"DROP INDEX IF EXISTS {_INDEX_NAME}")
