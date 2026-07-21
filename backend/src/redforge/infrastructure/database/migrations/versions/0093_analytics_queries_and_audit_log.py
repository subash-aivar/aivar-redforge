"""0093 — M33 Phase 2 analytics queries and audit log.

Migration chain: 0092 → 0093.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0093"
down_revision: str = "0092"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "analytics_queries",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("template", sa.Text(), nullable=False),
        sa.Column("domain", sa.String(64), nullable=False),
        sa.Column("parameters_json", postgresql.JSONB(), nullable=False),
        sa.Column("created_by", sa.String(256), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        schema="analytics",
    )
    op.create_index(
        "ix_analytics_queries_tenant",
        "analytics_queries",
        ["tenant_id"],
        schema="analytics",
    )

    op.create_table(
        "analytics_query_audit_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("query_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("execution_id", sa.String(128), nullable=False),
        sa.Column("executed_by", sa.String(256), nullable=False),
        sa.Column("parameters_json", postgresql.JSONB(), nullable=False),
        sa.Column("row_count", sa.Integer(), nullable=False),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=False),
        schema="analytics",
    )
    op.create_index(
        "ix_analytics_query_audit_tenant_at",
        "analytics_query_audit_log",
        ["tenant_id", "executed_at"],
        schema="analytics",
    )


def downgrade() -> None:
    op.drop_table("analytics_query_audit_log", schema="analytics")
    op.drop_table("analytics_queries", schema="analytics")
