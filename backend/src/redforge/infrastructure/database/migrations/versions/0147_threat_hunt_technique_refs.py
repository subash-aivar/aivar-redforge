"""0147 — M36 migration.

Migration chain: 0146 → 0147.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0147"
down_revision: str = "0146"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.create_table(
        "threat_hunt_technique_refs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("candidate_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("technique_id", sa.String(32), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        schema="threat_hunt",
    )
    op.create_index(
        "ix_hunt_tech_candidate",
        "threat_hunt_technique_refs",
        ["candidate_id"],
        schema="threat_hunt",
    )


def downgrade() -> None:

    op.drop_index(
        "ix_hunt_tech_candidate", table_name="threat_hunt_technique_refs", schema="threat_hunt"
    )
    op.drop_table("threat_hunt_technique_refs", schema="threat_hunt")
