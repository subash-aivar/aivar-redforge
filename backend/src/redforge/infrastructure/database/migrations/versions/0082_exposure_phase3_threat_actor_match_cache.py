"""0082 — M32 Phase 3 ThreatActorMatchCache + correlation keys.

Maps frozen plan migration 0046 onto the live Alembic chain after 0081:
- threat_actor_match_cache projection table
- cve_ids_json / asset_classes_json on exposure_records

Migration chain: 0081 → 0082.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0082"
down_revision: str = "0081"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "exposure_records",
        sa.Column(
            "cve_ids_json",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        schema="exposure",
    )
    op.add_column(
        "exposure_records",
        sa.Column(
            "asset_classes_json",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        schema="exposure",
    )

    op.create_table(
        "threat_actor_match_cache",
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("entries_json", postgresql.JSONB(), nullable=False),
        sa.Column("asset_class_entries_json", postgresql.JSONB(), nullable=False),
        sa.Column("technique_entries_json", postgresql.JSONB(), nullable=False),
        sa.Column("ioc_entries_json", postgresql.JSONB(), nullable=False),
        sa.Column("last_event_update_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_poll_update_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        schema="exposure",
    )


def downgrade() -> None:
    op.drop_table("threat_actor_match_cache", schema="exposure")
    op.drop_column("exposure_records", "asset_classes_json", schema="exposure")
    op.drop_column("exposure_records", "cve_ids_json", schema="exposure")
