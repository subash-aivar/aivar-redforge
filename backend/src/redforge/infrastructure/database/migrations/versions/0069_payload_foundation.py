"""0069 — M29 Phase 5 payload foundation.

Creates schema ``payload`` with:
- payloads (governance registry aggregate)
- plugin_registrations (execution plugin registry)
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0069"
down_revision: str = "0068"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_SCHEMA = "payload"


def upgrade() -> None:
    op.execute(sa.text(f"CREATE SCHEMA IF NOT EXISTS {_SCHEMA}"))

    op.create_table(
        "payloads",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("payload_key", sa.String(length=256), nullable=False),
        sa.Column("payload_type", sa.String(length=64), nullable=False),
        sa.Column("impact_ceiling", sa.String(length=32), nullable=False),
        sa.Column("approval_state", sa.String(length=32), nullable=False),
        sa.Column("current_version", sa.String(length=64), nullable=True),
        sa.Column("versions_json", postgresql.JSONB(), nullable=False),
        sa.Column("engagement_classes_json", postgresql.JSONB(), nullable=False),
        sa.Column("signature", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="0"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_payloads_tenant_key",
        "payloads",
        ["tenant_id", "payload_key"],
        unique=True,
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_payloads_tenant_state",
        "payloads",
        ["tenant_id", "approval_state"],
        schema=_SCHEMA,
    )

    op.create_table(
        "plugin_registrations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("plugin_type", sa.String(length=64), nullable=False),
        sa.Column("plugin_version", sa.String(length=64), nullable=False),
        sa.Column("plugin_hash", sa.String(length=64), nullable=False),
        sa.Column("technique_ids_json", postgresql.JSONB(), nullable=False),
        sa.Column("trust_level", sa.String(length=32), nullable=False),
        sa.Column("approval_state", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="0"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_plugin_registrations_tenant_state",
        "plugin_registrations",
        ["tenant_id", "approval_state"],
        schema=_SCHEMA,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_plugin_registrations_tenant_state",
        table_name="plugin_registrations",
        schema=_SCHEMA,
    )
    op.drop_table("plugin_registrations", schema=_SCHEMA)
    op.drop_index(
        "ix_payloads_tenant_state",
        table_name="payloads",
        schema=_SCHEMA,
    )
    op.drop_index(
        "ix_payloads_tenant_key",
        table_name="payloads",
        schema=_SCHEMA,
    )
    op.drop_table("payloads", schema=_SCHEMA)
    op.execute(sa.text(f"DROP SCHEMA IF EXISTS {_SCHEMA} CASCADE"))
