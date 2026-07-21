"""0084 — M32 Phase 5 ExposureReport persistence.

Maps frozen plan migration 0048 onto the live Alembic chain after 0083:
- exposure_reporting schema
- exposure_reports
- exposure_kpi_projections
- exposure_trend_projections

Migration chain: 0083 → 0084.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0084"
down_revision: str = "0083"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS exposure_reporting")

    op.create_table(
        "exposure_reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("report_type", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("template_id", sa.String(128), nullable=False),
        sa.Column("narrative", sa.Text(), nullable=False),
        sa.Column("content_json", postgresql.JSONB(), nullable=False),
        sa.Column("generated_by", sa.String(256), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("time_range_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("time_range_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        schema="exposure_reporting",
    )
    op.create_index(
        "ix_exposure_reports_tenant_id",
        "exposure_reports",
        ["tenant_id"],
        schema="exposure_reporting",
    )

    op.create_table(
        "exposure_kpi_projections",
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("kpi_json", postgresql.JSONB(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        schema="exposure_reporting",
    )

    op.create_table(
        "exposure_trend_projections",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_exposure_score", sa.Float(), nullable=False),
        sa.Column("asset_count", sa.Integer(), nullable=False),
        sa.Column("score_input_version", sa.String(64), nullable=False),
        sa.Column("computed_at", sa.DateTime(timezone=True), nullable=False),
        schema="exposure_reporting",
    )
    op.create_index(
        "ix_exposure_trend_projections_tenant_id",
        "exposure_trend_projections",
        ["tenant_id"],
        schema="exposure_reporting",
    )


def downgrade() -> None:
    op.drop_index(
        "ix_exposure_trend_projections_tenant_id",
        table_name="exposure_trend_projections",
        schema="exposure_reporting",
    )
    op.drop_table("exposure_trend_projections", schema="exposure_reporting")
    op.drop_table("exposure_kpi_projections", schema="exposure_reporting")
    op.drop_index(
        "ix_exposure_reports_tenant_id",
        table_name="exposure_reports",
        schema="exposure_reporting",
    )
    op.drop_table("exposure_reports", schema="exposure_reporting")
    op.execute("DROP SCHEMA IF EXISTS exposure_reporting CASCADE")
