"""0068 — M29 Phase 5 evidence foundation.

Creates schema ``evidence`` with:
- execution_evidence (aggregate root metadata; payload in blob store)
- evidence_chains (one chain per operation)
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0068"
down_revision: str = "0067"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_SCHEMA = "evidence"


def upgrade() -> None:
    op.execute(sa.text(f"CREATE SCHEMA IF NOT EXISTS {_SCHEMA}"))

    op.create_table(
        "execution_evidence",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("evidence_type", sa.String(length=64), nullable=False),
        sa.Column("payload_hash", sa.String(length=64), nullable=False),
        sa.Column("storage_ref", sa.String(length=512), nullable=False),
        sa.Column("key_id", sa.String(length=256), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False),
        sa.Column("action_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("collected_by", sa.String(length=256), nullable=False),
        sa.Column("integrity_status", sa.String(length=32), nullable=False),
        sa.Column("retention_class", sa.String(length=32), nullable=False),
        sa.Column("corrections_ref", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("custody_chain_json", postgresql.JSONB(), nullable=False),
        sa.Column(
            "quarantined",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "retention_expired",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="0"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_execution_evidence_tenant_operation",
        "execution_evidence",
        ["tenant_id", "operation_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_execution_evidence_tenant_action",
        "execution_evidence",
        ["tenant_id", "action_id"],
        schema=_SCHEMA,
    )

    op.create_table(
        "evidence_chains",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("chain_hash", sa.String(length=64), nullable=False),
        sa.Column("integrity_status", sa.String(length=32), nullable=False),
        sa.Column("entries_json", postgresql.JSONB(), nullable=False),
        sa.Column(
            "sealed_by_operator_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
        sa.Column("sealed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("sealer_role", sa.String(length=128), nullable=True),
        sa.Column("seal_signature", sa.Text(), nullable=True),
        sa.Column(
            "submission_destination_ref",
            sa.String(length=512),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="0"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_evidence_chains_tenant_operation",
        "evidence_chains",
        ["tenant_id", "operation_id"],
        unique=True,
        schema=_SCHEMA,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_evidence_chains_tenant_operation",
        table_name="evidence_chains",
        schema=_SCHEMA,
    )
    op.drop_table("evidence_chains", schema=_SCHEMA)
    op.drop_index(
        "ix_execution_evidence_tenant_action",
        table_name="execution_evidence",
        schema=_SCHEMA,
    )
    op.drop_index(
        "ix_execution_evidence_tenant_operation",
        table_name="execution_evidence",
        schema=_SCHEMA,
    )
    op.drop_table("execution_evidence", schema=_SCHEMA)
    op.execute(sa.text(f"DROP SCHEMA IF EXISTS {_SCHEMA} CASCADE"))
