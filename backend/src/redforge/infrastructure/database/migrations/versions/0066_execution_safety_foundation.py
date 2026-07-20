"""0066 — M29 Phase 3 execution safety foundation.

Creates execution schema tables: kill_switch_states, execution_journals,
journal_entries. No attack actions or workers (Phase 4).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0066"
down_revision: str = "0065"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_SCHEMA = "execution"


def upgrade() -> None:
    op.execute(sa.text(f"CREATE SCHEMA IF NOT EXISTS {_SCHEMA}"))

    op.create_table(
        "kill_switch_states",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scope", sa.String(length=32), nullable=False),
        sa.Column("scope_ref", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("armed_state", sa.String(length=32), nullable=False),
        sa.Column("trigger_authority_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("trigger_authority_role", sa.String(length=128), nullable=True),
        sa.Column("trigger_reason", sa.Text(), nullable=True),
        sa.Column("trigger_timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column("trigger_hash", sa.String(length=64), nullable=True),
        sa.Column("release_authority_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("release_authority_role", sa.String(length=128), nullable=True),
        sa.Column("release_countersign_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("release_countersign_role", sa.String(length=128), nullable=True),
        sa.Column("release_timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="0"),
        sa.UniqueConstraint(
            "tenant_id",
            "scope",
            "scope_ref",
            name="uq_kill_switch_tenant_scope_ref",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_kill_switch_tenant_scope",
        "kill_switch_states",
        ["tenant_id", "scope"],
        schema=_SCHEMA,
    )

    op.create_table(
        "execution_journals",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="0"),
        sa.UniqueConstraint(
            "tenant_id",
            "engagement_id",
            name="uq_execution_journals_tenant_engagement",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_execution_journals_tenant_engagement",
        "execution_journals",
        ["tenant_id", "engagement_id"],
        schema=_SCHEMA,
    )

    op.create_table(
        "journal_entries",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("journal_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("entry_type", sa.String(length=64), nullable=False),
        sa.Column("sequence_number", sa.Integer(), nullable=False),
        sa.Column("entry_hash", sa.String(length=64), nullable=False),
        sa.Column("previous_entry_hash", sa.String(length=64), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("attribution_operator_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("system_attribution", sa.String(length=128), nullable=True),
        sa.Column("corrects_ref", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["journal_id"],
            [f"{_SCHEMA}.execution_journals.id"],
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "journal_id",
            "sequence_number",
            name="uq_journal_entries_journal_seq",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_journal_entries_journal_seq",
        "journal_entries",
        ["journal_id", "sequence_number"],
        schema=_SCHEMA,
    )


def downgrade() -> None:
    op.drop_index("ix_journal_entries_journal_seq", table_name="journal_entries", schema=_SCHEMA)
    op.drop_table("journal_entries", schema=_SCHEMA)
    op.drop_index(
        "ix_execution_journals_tenant_engagement",
        table_name="execution_journals",
        schema=_SCHEMA,
    )
    op.drop_table("execution_journals", schema=_SCHEMA)
    op.drop_index("ix_kill_switch_tenant_scope", table_name="kill_switch_states", schema=_SCHEMA)
    op.drop_table("kill_switch_states", schema=_SCHEMA)
    op.execute(sa.text(f"DROP SCHEMA IF EXISTS {_SCHEMA}"))
