"""automation_executions was missing TriggerRef.source_event_type.

domain/value_objects/refs.py::TriggerRef has three fields (source_context,
source_event_type, source_event_id); migration 0120 only gave
automation_executions columns for source_context (as
trigger_source_context) and source_event_id. source_event_type had nowhere
to persist to.

Migration chain: 0150 -> 0151.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0151"
down_revision: str = "0150"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "automation_executions",
        sa.Column(
            "trigger_source_event_type",
            sa.Text(),
            nullable=False,
            server_default="",
        ),
        schema="automated_action",
    )


def downgrade() -> None:
    op.drop_column("automation_executions", "trigger_source_event_type", schema="automated_action")
