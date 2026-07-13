"""Continuous Validation Scheduler, Security Drift Detection & Revalidation
Engine — M14.

Adds:
  - continuous_validation_policies: tenant-owned aggregate declaring
    what/how-often to continuously validate. Closed lifecycle (draft/
    active/paused/disabled), closed cadence (hourly/every_6_hours/
    daily/weekly — no client cron), bounded claim lease
    (claimed_at/claim_owner) for concurrent-scheduler-safe due-policy
    claiming.
  - validation_state_snapshots: immutable, normalized comparison
    artifact for one policy's ValidationExecution — never updated after
    creation, one row per execution.
  - security_drift_events: immutable, append-only live change feed —
    one row per detected canonical-state change, deduplicated within an
    execution's own comparison by (execution_id, category,
    identity_key).
  - validation_executions gains trigger/continuous_policy_id/
    scheduled_due_at — closed, server-assigned provenance (never
    client-writable, see ValidationExecution.__init__'s docstring). A
    partial unique index on (continuous_policy_id, scheduled_due_at)
    database-enforces the hard invariant that one due boundary can
    create at most one canonical ValidationExecution, even under
    concurrent scheduler claim.

No exploit payloads, no credential attacks, no scanner flags, no
arbitrary commands anywhere in this bounded context — see
domain/continuous_validation's module docstring.

Revision ID: 0022
"""

import sqlalchemy as sa
from alembic import op

revision: str = "0022"
down_revision: str = "0021"
branch_labels: None = None
depends_on: None = None


def upgrade() -> None:
    op.create_table(
        "continuous_validation_policies",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("target_id", sa.String(26), nullable=False),
        sa.Column("requester_user_id", sa.String(26), nullable=False),
        sa.Column("profile", sa.String(50), nullable=False),
        sa.Column("cadence", sa.String(20), nullable=False),
        sa.Column("lifecycle", sa.String(20), nullable=False),
        sa.Column("next_due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_scheduled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("claim_owner", sa.String(100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("id", "organization_id", name="ux_cvp_id_org"),
    )
    op.create_index(
        "ix_cvp_org_lifecycle", "continuous_validation_policies",
        ["organization_id", "lifecycle"],
    )
    op.create_index(
        "ix_cvp_org_target", "continuous_validation_policies",
        ["organization_id", "target_id"],
    )
    op.create_index(
        "ix_cvp_lifecycle_next_due", "continuous_validation_policies",
        ["lifecycle", "next_due_at"],
    )

    op.create_table(
        "validation_state_snapshots",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("continuous_policy_id", sa.String(26), nullable=False),
        sa.Column("execution_id", sa.String(26), nullable=False),
        sa.Column("schema_version", sa.Integer, nullable=False),
        sa.Column("resolved_ips", sa.JSON, nullable=False),
        sa.Column("reachable_ports", sa.JSON, nullable=False),
        sa.Column("services", sa.JSON, nullable=False),
        sa.Column("active_condition_keys", sa.JSON, nullable=False),
        sa.Column("active_correlation_keys", sa.JSON, nullable=False),
        sa.Column("content_fingerprint", sa.String(64), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["continuous_policy_id", "organization_id"],
            ["continuous_validation_policies.id", "continuous_validation_policies.organization_id"],
            name="fk_vss_same_tenant_policy",
        ),
        sa.UniqueConstraint("id", "organization_id", name="ux_vss_id_org"),
        sa.UniqueConstraint("execution_id", name="ux_vss_execution"),
    )
    op.create_index(
        "ix_vss_org_policy_captured", "validation_state_snapshots",
        ["organization_id", "continuous_policy_id", "captured_at"],
    )

    op.create_table(
        "security_drift_events",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("continuous_policy_id", sa.String(26), nullable=False),
        sa.Column("execution_id", sa.String(26), nullable=False),
        sa.Column("category", sa.String(40), nullable=False),
        sa.Column("identity_key", sa.String(200), nullable=False),
        sa.Column("summary", sa.String(500), nullable=False),
        sa.Column("detail", sa.JSON, nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["continuous_policy_id", "organization_id"],
            ["continuous_validation_policies.id", "continuous_validation_policies.organization_id"],
            name="fk_sde_same_tenant_policy",
        ),
        sa.ForeignKeyConstraint(
            ["execution_id", "organization_id"],
            ["validation_executions.id", "validation_executions.organization_id"],
            name="fk_sde_same_tenant_execution",
        ),
        sa.UniqueConstraint("id", "organization_id", name="ux_sde_id_org"),
        sa.UniqueConstraint(
            "execution_id", "category", "identity_key", name="ux_sde_execution_category_identity",
        ),
    )
    op.create_index(
        "ix_sde_org_policy_detected", "security_drift_events",
        ["organization_id", "continuous_policy_id", "detected_at"],
    )

    op.add_column(
        "validation_executions",
        sa.Column("trigger", sa.String(20), nullable=False, server_default="manual"),
    )
    op.add_column(
        "validation_executions",
        sa.Column("continuous_policy_id", sa.String(26), nullable=True),
    )
    op.add_column(
        "validation_executions",
        sa.Column("scheduled_due_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ux_validation_executions_policy_due",
        "validation_executions",
        ["continuous_policy_id", "scheduled_due_at"],
        unique=True,
        postgresql_where=sa.text("continuous_policy_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("ux_validation_executions_policy_due", table_name="validation_executions")
    op.drop_column("validation_executions", "scheduled_due_at")
    op.drop_column("validation_executions", "continuous_policy_id")
    op.drop_column("validation_executions", "trigger")

    op.drop_index("ix_sde_org_policy_detected", table_name="security_drift_events")
    op.drop_table("security_drift_events")

    op.drop_index("ix_vss_org_policy_captured", table_name="validation_state_snapshots")
    op.drop_table("validation_state_snapshots")

    op.drop_index("ix_cvp_lifecycle_next_due", table_name="continuous_validation_policies")
    op.drop_index("ix_cvp_org_target", table_name="continuous_validation_policies")
    op.drop_index("ix_cvp_org_lifecycle", table_name="continuous_validation_policies")
    op.drop_table("continuous_validation_policies")
