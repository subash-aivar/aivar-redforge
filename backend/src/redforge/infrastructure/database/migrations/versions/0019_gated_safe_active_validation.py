"""Gated Safe Active Validation foundation — M11.

The first real execution layer behind M10's ExecutionPolicyService
boundary: bounded, non-destructive, real network validation (DNS/TCP/
TLS/HTTP) against an authorized canonical AITarget.

Adds:
  - validation_executions: canonical, tenant-owned execution record.
    Lifecycle: pending -> policy_checking -> authorized -> running ->
    completed/partially_completed/failed, or policy_checking/authorized
    -> denied, or any non-terminal status -> cancelled.
  - validation_execution_steps: bounded, ordered step snapshot owned by
    one execution. Composite-FK tenant integrity (same pattern M4/M5/
    M10 established), unique (execution_id, order_index).
  - validation_execution_events: immutable, append-only live-progress
    log. Composite-FK tenant integrity, unique (execution_id, sequence)
    for strict per-execution ordering, plus an (organization_id,
    occurred_at) index for cross-execution polling.

No M12 schema. No credentials, cookies, raw Authorization headers, or
full response bodies are ever columns here — only bounded, sanitized
evidence (see application/validation_execution/execution_service.py's
`_ev()` helper and network_adapters.py's redacted-header handling).

Revision ID: 0019
"""

import sqlalchemy as sa
from alembic import op

revision: str = "0019"
down_revision: str = "0018"
branch_labels: None = None
depends_on: None = None


def upgrade() -> None:
    op.create_table(
        "validation_executions",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("target_id", sa.String(26), nullable=False),
        sa.Column("requester_user_id", sa.String(26), nullable=False),
        sa.Column("profile", sa.String(50), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("policy_decision_id", sa.String(26), nullable=True),
        sa.Column("policy_reason_code", sa.String(40), nullable=True),
        sa.Column("cancellation_requested", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("limits", sa.JSON, nullable=False),
        sa.Column("failure_reason", sa.String(500), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("id", "organization_id", name="ux_validation_executions_id_org"),
    )
    op.create_index(
        "ix_validation_executions_org_status",
        "validation_executions", ["organization_id", "status"],
    )
    op.create_index(
        "ix_validation_executions_org_target",
        "validation_executions", ["organization_id", "target_id"],
    )
    op.create_index(
        "ix_validation_executions_org_created",
        "validation_executions", ["organization_id", "created_at"],
    )

    op.create_table(
        "validation_execution_steps",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("execution_id", sa.String(26), nullable=False),
        sa.Column("step_type", sa.String(30), nullable=False),
        sa.Column("order_index", sa.Integer, nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("evidence", sa.JSON, nullable=False),
        sa.Column("error_category", sa.String(40), nullable=True),
        sa.ForeignKeyConstraint(
            ["execution_id", "organization_id"],
            ["validation_executions.id", "validation_executions.organization_id"],
            name="fk_validation_step_same_tenant",
        ),
        sa.UniqueConstraint("execution_id", "order_index", name="ux_validation_step_order"),
    )
    op.create_index(
        "ix_validation_steps_org", "validation_execution_steps", ["organization_id"],
    )
    op.create_index(
        "ix_validation_steps_execution_id", "validation_execution_steps", ["execution_id"],
    )

    op.create_table(
        "validation_execution_events",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("execution_id", sa.String(26), nullable=False),
        sa.Column("sequence", sa.Integer, nullable=False),
        sa.Column("event_type", sa.String(40), nullable=False),
        sa.Column("payload", sa.JSON, nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["execution_id", "organization_id"],
            ["validation_executions.id", "validation_executions.organization_id"],
            name="fk_validation_event_same_tenant",
        ),
        sa.UniqueConstraint("execution_id", "sequence", name="ux_validation_event_sequence"),
    )
    op.create_index(
        "ix_validation_events_org_execution_seq",
        "validation_execution_events", ["organization_id", "execution_id", "sequence"],
    )
    op.create_index(
        "ix_validation_events_org_occurred",
        "validation_execution_events", ["organization_id", "occurred_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_validation_events_org_occurred", table_name="validation_execution_events")
    op.drop_index(
        "ix_validation_events_org_execution_seq", table_name="validation_execution_events",
    )
    op.drop_table("validation_execution_events")

    op.drop_index("ix_validation_steps_execution_id", table_name="validation_execution_steps")
    op.drop_index("ix_validation_steps_org", table_name="validation_execution_steps")
    op.drop_table("validation_execution_steps")

    op.drop_index("ix_validation_executions_org_created", table_name="validation_executions")
    op.drop_index("ix_validation_executions_org_target", table_name="validation_executions")
    op.drop_index("ix_validation_executions_org_status", table_name="validation_executions")
    op.drop_table("validation_executions")
