"""DLQ exhausted status and in-flight reservation — Sprint 31.

Adds:
  - reserved_until: TIMESTAMPTZ — set when a worker claims an entry for replay.
    Entries with expired reserved_until are re-claimable by other workers.
    NULL means the entry has not been claimed (status=pending or requeued) or
    was already replayed/exhausted.
  - exhausted_at: TIMESTAMPTZ — set when an entry is marked terminal (exhausted).
    Entries in this state are never picked up for replay again.

Status lifecycle after this migration:
    pending → requeued → in_flight → (success) deleted
                                   → (failure) requeued
                                   → (retries exhausted) exhausted

Partial index for in-flight claim query: status IN ('requeued','in_flight')
with reserved_until IS NULL or expired — supports the atomic UPDATE ... RETURNING
pattern without a full table scan.

Revision ID: 0009
Revises: 0008
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: str = "0008"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "dead_letter_entries",
        sa.Column("reserved_until", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "dead_letter_entries",
        sa.Column("exhausted_at", sa.DateTime(timezone=True), nullable=True),
    )

    # Partial index for the atomic claim query:
    # WHERE status = 'requeued' OR (status = 'in_flight' AND reserved_until < NOW())
    op.execute(
        "CREATE INDEX ix_dle_claimable ON dead_letter_entries (last_failed_at ASC) "
        "WHERE status IN ('requeued', 'in_flight')"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_dle_claimable")
    op.drop_column("dead_letter_entries", "exhausted_at")
    op.drop_column("dead_letter_entries", "reserved_until")
