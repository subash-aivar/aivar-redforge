"""0059 — M28 Phase 2 TelemetrySource foundation.

Adds telemetry_sources metadata table only.
No packs, executions, findings, exceptions, or evidence tables.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0059"
down_revision: str = "0058"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_SCHEMA = "detection"


def upgrade() -> None:
    op.execute(sa.text(f"CREATE SCHEMA IF NOT EXISTS {_SCHEMA}"))

    op.create_table(
        "telemetry_sources",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("source_type", sa.String(length=64), nullable=False),
        sa.Column("trust_level", sa.String(length=32), nullable=False),
        sa.Column("lifecycle_state", sa.String(length=32), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("schema_version", sa.String(length=64), nullable=False),
        sa.Column("schema_json", postgresql.JSONB(), nullable=False),
        sa.Column("connection_json", postgresql.JSONB(), nullable=False),
        sa.Column("health_status", sa.String(length=32), nullable=False),
        sa.Column("health_json", postgresql.JSONB(), nullable=False),
        sa.Column("latency_expected_seconds", sa.Float(), nullable=False),
        sa.Column("latency_max_seconds", sa.Float(), nullable=True),
        sa.Column("retention_seconds", sa.Float(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="0"),
        sa.UniqueConstraint(
            "tenant_id", "name", name="uq_telemetry_sources_tenant_name"
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_telemetry_sources_tenant_id",
        "telemetry_sources",
        ["tenant_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_telemetry_sources_tenant_lifecycle",
        "telemetry_sources",
        ["tenant_id", "lifecycle_state"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_telemetry_sources_tenant_type",
        "telemetry_sources",
        ["tenant_id", "source_type"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_telemetry_sources_tenant_health",
        "telemetry_sources",
        ["tenant_id", "health_status"],
        schema=_SCHEMA,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_telemetry_sources_tenant_health",
        table_name="telemetry_sources",
        schema=_SCHEMA,
    )
    op.drop_index(
        "ix_telemetry_sources_tenant_type",
        table_name="telemetry_sources",
        schema=_SCHEMA,
    )
    op.drop_index(
        "ix_telemetry_sources_tenant_lifecycle",
        table_name="telemetry_sources",
        schema=_SCHEMA,
    )
    op.drop_index(
        "ix_telemetry_sources_tenant_id",
        table_name="telemetry_sources",
        schema=_SCHEMA,
    )
    op.drop_table("telemetry_sources", schema=_SCHEMA)
