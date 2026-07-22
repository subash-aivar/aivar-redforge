"""Playbook approval records — quorum approvals had no column to persist to.

Playbook.approved_by (domain/aggregates/playbook.py) is a list[ApprovalRecord]
tracking the quorum of reviewers who approved a playbook for UNDER_REVIEW ->
APPROVED — required domain state for the approval workflow. Migration 0114
(playbooks_core) never gave it a column, which is why PlaybookContainer's
persistence conversion (this same change) needed a real migration rather than
just a repository: there was nowhere to write this data.

Migration chain: 0149 -> 0150.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0150"
down_revision: str = "0149"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "playbooks",
        sa.Column(
            "approved_by_json",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        schema="playbook",
    )


def downgrade() -> None:
    op.drop_column("playbooks", "approved_by_json", schema="playbook")
