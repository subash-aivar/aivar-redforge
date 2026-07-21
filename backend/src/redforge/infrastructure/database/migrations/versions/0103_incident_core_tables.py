"""0103 — M34 migration.

Migration chain: 0102 → 0103.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0103"
down_revision: str = "0102"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS incident")
    op.create_table(
        "incidents",
        sa.Column("incident_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("phase", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(64), nullable=False),
        sa.Column("trigger_type", sa.String(64), nullable=False),
        sa.Column("classification_method", sa.String(64), nullable=True),
        sa.Column("classified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("contained_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("eradicated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("recovered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolution_type", sa.String(64), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        schema="incident",
    )
    op.create_index("ix_incidents_tenant_phase", "incidents", ["tenant_id", "phase"], schema="incident")
    op.create_table(
        "incident_timeline_entries",
        sa.Column("entry_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("entry_type", sa.String(64), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("actor", sa.String(256), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("details", postgresql.JSONB(), nullable=False),
        schema="incident",
    )
    op.create_table(
        "incident_tags",
        sa.Column("incident_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tag_key", sa.String(128), primary_key=True),
        sa.Column("tag_value", sa.String(512), nullable=False),
        schema="incident",
    )

def downgrade() -> None:
    op.drop_table("incident_tags", schema="incident")
    op.drop_table("incident_timeline_entries", schema="incident")
    op.drop_table("incidents", schema="incident")
    op.execute("DROP SCHEMA IF EXISTS incident CASCADE")
