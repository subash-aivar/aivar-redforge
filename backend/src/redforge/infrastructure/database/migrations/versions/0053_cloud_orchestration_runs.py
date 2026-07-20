"""0053 — M26 Phase 8 Cloud Platform Orchestration runs.

Stores orchestration run records (operational audit trail) and optional
last-validation reports under cloud_security.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0053"
down_revision: str = "0052"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_SCHEMA = "cloud_security"


def upgrade() -> None:
    op.create_table(
        "cloud_orchestration_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", sa.String(length=26), nullable=False),
        sa.Column("scope", sa.String(length=32), nullable=False),
        sa.Column("target_id", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("steps", postgresql.JSONB(), nullable=False),
        sa.Column("diagnostics", postgresql.JSONB(), nullable=False),
        sa.Column("operation_id", sa.String(length=64), nullable=False),
        sa.Column("correlation_id", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("request_id", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cloud_orchestration_runs_org_started",
        "cloud_orchestration_runs",
        ["organization_id", "started_at"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cloud_orchestration_runs_org_status",
        "cloud_orchestration_runs",
        ["organization_id", "status"],
        schema=_SCHEMA,
    )

    op.create_table(
        "cloud_platform_validation_reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", sa.String(length=26), nullable=False),
        sa.Column("report", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "organization_id",
            name="uq_cloud_platform_validation_reports_org",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cloud_platform_validation_reports_organization_id",
        "cloud_platform_validation_reports",
        ["organization_id"],
        schema=_SCHEMA,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_cloud_platform_validation_reports_organization_id",
        table_name="cloud_platform_validation_reports",
        schema=_SCHEMA,
    )
    op.drop_table("cloud_platform_validation_reports", schema=_SCHEMA)
    op.drop_index(
        "ix_cloud_orchestration_runs_org_status",
        table_name="cloud_orchestration_runs",
        schema=_SCHEMA,
    )
    op.drop_index(
        "ix_cloud_orchestration_runs_org_started",
        table_name="cloud_orchestration_runs",
        schema=_SCHEMA,
    )
    op.drop_table("cloud_orchestration_runs", schema=_SCHEMA)
