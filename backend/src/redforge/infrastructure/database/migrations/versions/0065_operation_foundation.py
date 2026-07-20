"""0065 — M29 Phase 2 operation foundation.

Creates operation schema tables: operations, execution_steps, step_dependencies,
operation_approvals, operation_objectives, execution_plan_versions.

No execution workers, kill switch, or evidence tables.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0065"
down_revision: str = "0064"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_SCHEMA = "operation"


def upgrade() -> None:
    op.execute(sa.text(f"CREATE SCHEMA IF NOT EXISTS {_SCHEMA}"))

    op.create_table(
        "operations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("classification", sa.String(length=64), nullable=False),
        sa.Column("state", sa.String(length=48), nullable=False),
        sa.Column("risk", sa.String(length=32), nullable=False),
        sa.Column("abort_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="0"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_operations_tenant_id", "operations", ["tenant_id"], schema=_SCHEMA
    )
    op.create_index(
        "ix_operations_tenant_engagement",
        "operations",
        ["tenant_id", "engagement_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_operations_tenant_state",
        "operations",
        ["tenant_id", "state"],
        schema=_SCHEMA,
    )

    op.create_table(
        "execution_steps",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("step_type", sa.String(length=48), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("impact_ceiling", sa.String(length=32), nullable=True),
        sa.Column(
            "modifies_persistent_state",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("constraints_json", postgresql.JSONB(), nullable=False),
        sa.Column("technique_json", postgresql.JSONB(), nullable=True),
        sa.Column("target_asset_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("mitre_json", postgresql.JSONB(), nullable=True),
        sa.Column("rate_limit_json", postgresql.JSONB(), nullable=True),
        sa.Column("window_json", postgresql.JSONB(), nullable=True),
        sa.Column("output_ref", sa.String(length=512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["operation_id"],
            [f"{_SCHEMA}.operations.id"],
            ondelete="CASCADE",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_execution_steps_tenant_operation",
        "execution_steps",
        ["tenant_id", "operation_id"],
        schema=_SCHEMA,
    )

    op.create_table(
        "step_dependencies",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("from_step_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("to_step_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["operation_id"],
            [f"{_SCHEMA}.operations.id"],
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "operation_id",
            "from_step_id",
            "to_step_id",
            name="uq_step_dependencies_edge",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_step_dependencies_tenant_operation",
        "step_dependencies",
        ["tenant_id", "operation_id"],
        schema=_SCHEMA,
    )

    op.create_table(
        "operation_approvals",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("operator_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("authority", sa.String(length=64), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["operation_id"],
            [f"{_SCHEMA}.operations.id"],
            ondelete="CASCADE",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_operation_approvals_tenant_operation",
        "operation_approvals",
        ["tenant_id", "operation_id"],
        schema=_SCHEMA,
    )

    op.create_table(
        "operation_objectives",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("success_criteria", sa.Text(), nullable=False),
        sa.Column(
            "is_primary", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
        sa.ForeignKeyConstraint(
            ["operation_id"],
            [f"{_SCHEMA}.operations.id"],
            ondelete="CASCADE",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_operation_objectives_tenant_operation",
        "operation_objectives",
        ["tenant_id", "operation_id"],
        schema=_SCHEMA,
    )

    op.create_table(
        "execution_plan_versions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("operation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("snapshot", sa.Text(), nullable=False),
        sa.Column("plan_hash", sa.String(length=64), nullable=True),
        sa.Column("signed_by_operator_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("signed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("signature", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="0"),
        sa.UniqueConstraint(
            "tenant_id",
            "operation_id",
            "version_number",
            name="uq_plan_versions_op_number",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_plan_versions_tenant_operation",
        "execution_plan_versions",
        ["tenant_id", "operation_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_plan_versions_tenant_state",
        "execution_plan_versions",
        ["tenant_id", "state"],
        schema=_SCHEMA,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_plan_versions_tenant_state",
        table_name="execution_plan_versions",
        schema=_SCHEMA,
    )
    op.drop_index(
        "ix_plan_versions_tenant_operation",
        table_name="execution_plan_versions",
        schema=_SCHEMA,
    )
    op.drop_table("execution_plan_versions", schema=_SCHEMA)

    op.drop_index(
        "ix_operation_objectives_tenant_operation",
        table_name="operation_objectives",
        schema=_SCHEMA,
    )
    op.drop_table("operation_objectives", schema=_SCHEMA)

    op.drop_index(
        "ix_operation_approvals_tenant_operation",
        table_name="operation_approvals",
        schema=_SCHEMA,
    )
    op.drop_table("operation_approvals", schema=_SCHEMA)

    op.drop_index(
        "ix_step_dependencies_tenant_operation",
        table_name="step_dependencies",
        schema=_SCHEMA,
    )
    op.drop_table("step_dependencies", schema=_SCHEMA)

    op.drop_index(
        "ix_execution_steps_tenant_operation",
        table_name="execution_steps",
        schema=_SCHEMA,
    )
    op.drop_table("execution_steps", schema=_SCHEMA)

    op.drop_index("ix_operations_tenant_state", table_name="operations", schema=_SCHEMA)
    op.drop_index(
        "ix_operations_tenant_engagement", table_name="operations", schema=_SCHEMA
    )
    op.drop_index("ix_operations_tenant_id", table_name="operations", schema=_SCHEMA)
    op.drop_table("operations", schema=_SCHEMA)
    op.execute(sa.text(f"DROP SCHEMA IF EXISTS {_SCHEMA}"))
