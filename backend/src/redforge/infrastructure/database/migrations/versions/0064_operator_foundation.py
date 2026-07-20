"""0064 — M29 Phase 1 Operator foundation.

Creates schema operator with operators table.
Depends on 0063 (engagement foundation — created by engagement agent).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0064"
down_revision: str = "0063"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_SCHEMA = "operator"


def upgrade() -> None:
    op.execute(sa.text(f"CREATE SCHEMA IF NOT EXISTS {_SCHEMA}"))

    op.create_table(
        "operators",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("identity_ref", sa.String(length=256), nullable=False),
        sa.Column("display_name", sa.String(length=256), nullable=False),
        sa.Column("clearance_level", sa.String(length=32), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("certifications_json", postgresql.JSONB(), nullable=False),
        sa.Column("approval_scopes_json", postgresql.JSONB(), nullable=False),
        sa.Column("active_engagement_ids_json", postgresql.JSONB(), nullable=False),
        sa.Column("status_reason", sa.Text(), nullable=True),
        sa.Column("status_authority", sa.String(length=256), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_operator_operators_tenant_id",
        "operators",
        ["tenant_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_operator_operators_tenant_state",
        "operators",
        ["tenant_id", "state"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_operator_operators_tenant_identity",
        "operators",
        ["tenant_id", "identity_ref"],
        schema=_SCHEMA,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_operator_operators_tenant_identity",
        table_name="operators",
        schema=_SCHEMA,
    )
    op.drop_index(
        "ix_operator_operators_tenant_state",
        table_name="operators",
        schema=_SCHEMA,
    )
    op.drop_index(
        "ix_operator_operators_tenant_id",
        table_name="operators",
        schema=_SCHEMA,
    )
    op.drop_table("operators", schema=_SCHEMA)
    op.execute(sa.text(f"DROP SCHEMA IF EXISTS {_SCHEMA}"))
