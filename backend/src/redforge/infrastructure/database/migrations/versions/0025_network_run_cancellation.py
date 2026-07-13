"""Mid-run execution cancellation for NetworkValidationRun — M16 scenario #51.

Adds network_validation_runs.cancellation_requested: a monotonic,
tenant-scoped boolean flag decoupled from the `status` state machine.
Deliberately NOT touched by the repository's generic save() UPDATE
branch — it is mutated only by a dedicated atomic
`UPDATE ... RETURNING` repository method, so a long-lived in-memory
aggregate saved later (a stale read) can never overwrite a
cancellation request persisted by another session.

Revision ID: 0025
"""

import sqlalchemy as sa
from alembic import op

revision: str = "0025"
down_revision: str = "0024"
branch_labels: None = None
depends_on: None = None


def upgrade() -> None:
    op.add_column(
        "network_validation_runs",
        sa.Column(
            "cancellation_requested",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )


def downgrade() -> None:
    op.drop_column("network_validation_runs", "cancellation_requested")
