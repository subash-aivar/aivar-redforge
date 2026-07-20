"""0070 — M29 Phase 6 red-team read model foundation.

Creates JSONB-backed projection tables for engagement summaries, operation
timelines, technique rollups, detection coverage, evidence audit, and
operator activity.

Migration chain: 0067 → 0068 (evidence) → 0069 (payload) → 0070 (read models).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0070"
down_revision: str = "0069"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_SCHEMA = "execution"


def _view_table(name: str) -> None:
    op.create_table(
        name,
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("view_key", sa.String(length=128), nullable=False),
        sa.Column("payload_json", postgresql.JSONB(), nullable=False),
        sa.Column("last_event_id", sa.String(length=64), nullable=True),
        sa.Column("projection_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "tenant_id",
            "view_key",
            name=f"uq_{_SCHEMA}_{name}_tenant_view_key",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        f"ix_{_SCHEMA}_{name}_tenant",
        name,
        ["tenant_id"],
        schema=_SCHEMA,
    )


def upgrade() -> None:
    op.execute(sa.text(f"CREATE SCHEMA IF NOT EXISTS {_SCHEMA}"))

    for table in (
        "engagement_summary_views",
        "operation_timeline_views",
        "action_by_technique_views",
        "detection_coverage_reports",
        "evidence_audit_views",
        "operator_activity_views",
    ):
        _view_table(table)

    op.create_table(
        "red_team_projection_checkpoints",
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
            name="uq_execution_red_team_projection_checkpoints_tenant_name",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_execution_red_team_projection_checkpoints_tenant",
        "red_team_projection_checkpoints",
        ["tenant_id"],
        schema=_SCHEMA,
    )


def downgrade() -> None:
    op.drop_table("red_team_projection_checkpoints", schema=_SCHEMA)
    for table in (
        "operator_activity_views",
        "evidence_audit_views",
        "detection_coverage_reports",
        "action_by_technique_views",
        "operation_timeline_views",
        "engagement_summary_views",
    ):
        op.drop_table(table, schema=_SCHEMA)
