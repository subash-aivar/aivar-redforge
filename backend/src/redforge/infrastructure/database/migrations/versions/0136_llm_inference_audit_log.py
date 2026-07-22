"""0136 — M36 migration.

Migration chain: 0135 → 0136.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0136"
down_revision: str = "0135"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:

    op.create_table(
        "llm_inference_audit_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("model_id", sa.String(128), nullable=False),
        sa.Column("prompt_token_count", sa.Integer(), nullable=False),
        sa.Column("completion_token_count", sa.Integer(), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        schema="autonomous_intelligence",
    )
    op.create_index(
        "ix_llm_audit_tenant_at",
        "llm_inference_audit_log",
        ["tenant_id", "recorded_at"],
        schema="autonomous_intelligence",
    )


def downgrade() -> None:

    op.drop_index(
        "ix_llm_audit_tenant_at",
        table_name="llm_inference_audit_log",
        schema="autonomous_intelligence",
    )
    op.drop_table("llm_inference_audit_log", schema="autonomous_intelligence")
