"""0062 — M28 Phase 5 detection read models + projection checkpoints.

Creates projection checkpoint and read-model tables in the detection schema.
No Security Graph schema changes (uses existing security_graph_nodes/edges).
No dashboards.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0062"
down_revision: str = "0061"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_SCHEMA = "detection"


def upgrade() -> None:
    op.execute(sa.text(f"CREATE SCHEMA IF NOT EXISTS {_SCHEMA}"))

    op.create_table(
        "projection_checkpoints",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("projection_name", sa.String(length=128), nullable=False),
        sa.Column("projection_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("last_global_position", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("last_event_id", sa.String(length=64), nullable=True),
        sa.Column("events_processed", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "tenant_id",
            "projection_name",
            name="uq_detection_projection_checkpoints_tenant_name",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_detection_projection_checkpoints_tenant",
        "projection_checkpoints",
        ["tenant_id"],
        schema=_SCHEMA,
    )

    op.create_table(
        "coverage_matrix_views",
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("payload_json", postgresql.JSONB(), nullable=False),
        sa.Column("covered_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("gap_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_event_id", sa.String(length=64), nullable=True),
        sa.Column("projection_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        schema=_SCHEMA,
    )

    op.create_table(
        "finding_summary_views",
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("payload_json", postgresql.JSONB(), nullable=False),
        sa.Column("total_open", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_closed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_event_id", sa.String(length=64), nullable=True),
        sa.Column("projection_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        schema=_SCHEMA,
    )

    op.create_table(
        "execution_health_views",
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("payload_json", postgresql.JSONB(), nullable=False),
        sa.Column("total_executions", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failed_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_event_id", sa.String(length=64), nullable=True),
        sa.Column("projection_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        schema=_SCHEMA,
    )

    op.create_table(
        "exception_expiry_views",
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("payload_json", postgresql.JSONB(), nullable=False),
        sa.Column("active_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("pending_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("expired_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_event_id", sa.String(length=64), nullable=True),
        sa.Column("projection_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        schema=_SCHEMA,
    )

    op.create_table(
        "fp_profile_views",
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("payload_json", postgresql.JSONB(), nullable=False),
        sa.Column("last_event_id", sa.String(length=64), nullable=True),
        sa.Column("projection_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        schema=_SCHEMA,
    )

    op.create_table(
        "tenant_coverage_gap_views",
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("payload_json", postgresql.JSONB(), nullable=False),
        sa.Column("coverage_pct", sa.Float(), nullable=False, server_default="0"),
        sa.Column("last_event_id", sa.String(length=64), nullable=True),
        sa.Column("projection_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        schema=_SCHEMA,
    )


def downgrade() -> None:
    op.drop_table("tenant_coverage_gap_views", schema=_SCHEMA)
    op.drop_table("fp_profile_views", schema=_SCHEMA)
    op.drop_table("exception_expiry_views", schema=_SCHEMA)
    op.drop_table("execution_health_views", schema=_SCHEMA)
    op.drop_table("finding_summary_views", schema=_SCHEMA)
    op.drop_table("coverage_matrix_views", schema=_SCHEMA)
    op.drop_table("projection_checkpoints", schema=_SCHEMA)
