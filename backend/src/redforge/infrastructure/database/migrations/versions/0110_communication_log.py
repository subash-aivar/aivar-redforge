"""0110 — M34 migration.

Migration chain: 0109 → 0110.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0110"
down_revision: str = "0109"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "incident_communication_log_entries",
        sa.Column("entry_id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("author", sa.String(256), nullable=False),
        sa.Column("recipient_summary", sa.String(512), nullable=False),
        sa.Column("communication_type", sa.String(64), nullable=False),
        sa.Column("logged_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("entry_sequence", sa.Integer(), nullable=False),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("entry_hash", sa.String(64), nullable=False),
        schema="incident",
    )
    op.execute("REVOKE UPDATE, DELETE ON incident.incident_communication_log_entries FROM PUBLIC")

def downgrade() -> None:
    op.drop_table("incident_communication_log_entries", schema="incident")
