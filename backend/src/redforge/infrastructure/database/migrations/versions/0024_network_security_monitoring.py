"""Advanced Network Security & Continuous Network Monitoring — M16.

Adds:
  - network_monitoring_policies: tenant-owned continuous network
    monitoring configuration for one NETWORK/IP_ADDRESS AIAsset.
    Mirrors continuous_validation_policies exactly (same lifecycle,
    same cadence, same claim-lease columns) — a parallel table rather
    than reuse because target_asset_id references an AIAsset, not an
    AITarget (see domain/network_security/__init__.py's reuse table
    for why ContinuousValidationPolicy's target_id shape could not be
    reused directly).
  - network_validation_runs: execution-lifecycle truth for one network
    validation attempt. Mirrors validation_executions.
  - network_state_snapshots / network_drift_events: mirrors
    validation_state_snapshots / security_drift_events exactly (same
    normalized fields, same dedup discipline) but FK'd to this
    context's own policy/run tables rather than M14's.
  - network_observations: durable, bounded, allowlisted observation
    persistence (M3 explicitly deferred this; M16 revisits it). No raw
    packet/banner/credential/secret data — see
    application/network_security/orchestrator.py's docstring for the
    exact allowlisted fields.
  - network_monitoring_policy_lifecycle_events /
    network_validation_run_events: append-only logs feeding the M15
    Security Operations projection registry, mirroring
    continuous_validation_policy_lifecycle_events /
    validation_execution_events exactly.

No exploit payloads, no credential attacks, no scanner flags, no
arbitrary commands anywhere in this bounded context.

Revision ID: 0024
"""

import sqlalchemy as sa
from alembic import op

revision: str = "0024"
down_revision: str = "0023"
branch_labels: None = None
depends_on: None = None


def upgrade() -> None:
    op.create_table(
        "network_monitoring_policies",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("target_asset_id", sa.String(26), nullable=False),
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
        sa.ForeignKeyConstraint(["target_asset_id"], ["ai_assets.id"], name="fk_nmp_target_asset"),
        sa.UniqueConstraint("id", "organization_id", name="ux_nmp_id_org"),
    )
    op.create_index(
        "ix_nmp_org_lifecycle", "network_monitoring_policies", ["organization_id", "lifecycle"],
    )
    op.create_index(
        "ix_nmp_org_target", "network_monitoring_policies", ["organization_id", "target_asset_id"],
    )
    op.create_index(
        "ix_nmp_lifecycle_next_due", "network_monitoring_policies", ["lifecycle", "next_due_at"],
    )

    op.create_table(
        "network_validation_runs",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("target_asset_id", sa.String(26), nullable=False),
        sa.Column("requester_user_id", sa.String(26), nullable=False),
        sa.Column("profile", sa.String(50), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("trigger", sa.String(20), nullable=False, server_default="manual"),
        sa.Column("continuous_policy_id", sa.String(26), nullable=True),
        sa.Column("scheduled_due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("authorization_id", sa.String(26), nullable=True),
        sa.Column("failure_reason", sa.String(500), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["target_asset_id"], ["ai_assets.id"], name="fk_nvr_target_asset"),
        sa.ForeignKeyConstraint(
            ["continuous_policy_id", "organization_id"],
            ["network_monitoring_policies.id", "network_monitoring_policies.organization_id"],
            name="fk_nvr_same_tenant_policy",
        ),
        sa.UniqueConstraint("id", "organization_id", name="ux_nvr_id_org"),
    )
    op.create_index(
        "ix_nvr_org_status", "network_validation_runs", ["organization_id", "status"],
    )
    op.create_index(
        "ix_nvr_org_target", "network_validation_runs", ["organization_id", "target_asset_id"],
    )
    op.create_index(
        "ix_nvr_org_created", "network_validation_runs", ["organization_id", "created_at"],
    )
    op.create_index(
        "ux_nvr_policy_due", "network_validation_runs",
        ["continuous_policy_id", "scheduled_due_at"], unique=True,
        postgresql_where=sa.text("continuous_policy_id IS NOT NULL"),
    )

    op.create_table(
        "network_state_snapshots",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("policy_id", sa.String(26), nullable=False),
        sa.Column("run_id", sa.String(26), nullable=False),
        sa.Column("schema_version", sa.Integer, nullable=False),
        sa.Column("resolved_ips", sa.JSON, nullable=False),
        sa.Column("reachable_ports", sa.JSON, nullable=False),
        sa.Column("services", sa.JSON, nullable=False),
        sa.Column("active_condition_keys", sa.JSON, nullable=False),
        sa.Column("active_correlation_keys", sa.JSON, nullable=False),
        sa.Column("content_fingerprint", sa.String(64), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["policy_id", "organization_id"],
            ["network_monitoring_policies.id", "network_monitoring_policies.organization_id"],
            name="fk_nss_same_tenant_policy",
        ),
        sa.ForeignKeyConstraint(
            ["run_id", "organization_id"],
            ["network_validation_runs.id", "network_validation_runs.organization_id"],
            name="fk_nss_same_tenant_run",
        ),
        sa.UniqueConstraint("id", "organization_id", name="ux_nss_id_org"),
        sa.UniqueConstraint("run_id", name="ux_nss_run"),
    )
    op.create_index(
        "ix_nss_org_policy_captured", "network_state_snapshots",
        ["organization_id", "policy_id", "captured_at"],
    )

    op.create_table(
        "network_drift_events",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("policy_id", sa.String(26), nullable=False),
        sa.Column("run_id", sa.String(26), nullable=False),
        sa.Column("category", sa.String(40), nullable=False),
        sa.Column("identity_key", sa.String(200), nullable=False),
        sa.Column("summary", sa.String(500), nullable=False),
        sa.Column("detail", sa.JSON, nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["policy_id", "organization_id"],
            ["network_monitoring_policies.id", "network_monitoring_policies.organization_id"],
            name="fk_nde_same_tenant_policy",
        ),
        sa.ForeignKeyConstraint(
            ["run_id", "organization_id"],
            ["network_validation_runs.id", "network_validation_runs.organization_id"],
            name="fk_nde_same_tenant_run",
        ),
        sa.UniqueConstraint("id", "organization_id", name="ux_nde_id_org"),
        sa.UniqueConstraint(
            "run_id", "category", "identity_key", name="ux_nde_run_category_identity",
        ),
    )
    op.create_index(
        "ix_nde_org_policy_detected", "network_drift_events",
        ["organization_id", "policy_id", "detected_at"],
    )

    op.create_table(
        "network_observations",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("run_id", sa.String(26), nullable=False),
        sa.Column("asset_id", sa.String(26), nullable=False),
        sa.Column("observation_type", sa.String(40), nullable=False),
        sa.Column("method", sa.String(40), nullable=False),
        sa.Column("outcome", sa.String(40), nullable=False),
        sa.Column("schema_version", sa.Integer, nullable=False),
        sa.Column("data", sa.JSON, nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["run_id", "organization_id"],
            ["network_validation_runs.id", "network_validation_runs.organization_id"],
            name="fk_no_same_tenant_run",
        ),
        sa.ForeignKeyConstraint(["asset_id"], ["ai_assets.id"], name="fk_no_asset"),
        sa.UniqueConstraint("id", "organization_id", name="ux_no_id_org"),
    )
    op.create_index(
        "ix_no_org_asset_observed", "network_observations",
        ["organization_id", "asset_id", "observed_at"],
    )
    op.create_index("ix_no_org_run", "network_observations", ["organization_id", "run_id"])

    op.create_table(
        "network_monitoring_policy_lifecycle_events",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("policy_id", sa.String(26), nullable=False),
        sa.Column("event_type", sa.String(40), nullable=False),
        sa.Column("detail", sa.JSON, nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["policy_id", "organization_id"],
            ["network_monitoring_policies.id", "network_monitoring_policies.organization_id"],
            name="fk_nmple_same_tenant_policy",
        ),
        sa.UniqueConstraint("id", "organization_id", name="ux_nmple_id_org"),
    )
    op.create_index(
        "ix_nmple_org_occurred", "network_monitoring_policy_lifecycle_events",
        ["organization_id", "occurred_at"],
    )

    op.create_table(
        "network_validation_run_events",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("run_id", sa.String(26), nullable=False),
        sa.Column("event_type", sa.String(40), nullable=False),
        sa.Column("payload", sa.JSON, nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["run_id", "organization_id"],
            ["network_validation_runs.id", "network_validation_runs.organization_id"],
            name="fk_nvre_same_tenant_run",
        ),
        sa.UniqueConstraint("id", "organization_id", name="ux_nvre_id_org"),
    )
    op.create_index(
        "ix_nvre_org_occurred", "network_validation_run_events",
        ["organization_id", "occurred_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_nvre_org_occurred", table_name="network_validation_run_events")
    op.drop_table("network_validation_run_events")

    op.drop_index(
        "ix_nmple_org_occurred", table_name="network_monitoring_policy_lifecycle_events",
    )
    op.drop_table("network_monitoring_policy_lifecycle_events")

    op.drop_index("ix_no_org_run", table_name="network_observations")
    op.drop_index("ix_no_org_asset_observed", table_name="network_observations")
    op.drop_table("network_observations")

    op.drop_index("ix_nde_org_policy_detected", table_name="network_drift_events")
    op.drop_table("network_drift_events")

    op.drop_index("ix_nss_org_policy_captured", table_name="network_state_snapshots")
    op.drop_table("network_state_snapshots")

    op.drop_index("ux_nvr_policy_due", table_name="network_validation_runs")
    op.drop_index("ix_nvr_org_created", table_name="network_validation_runs")
    op.drop_index("ix_nvr_org_target", table_name="network_validation_runs")
    op.drop_index("ix_nvr_org_status", table_name="network_validation_runs")
    op.drop_table("network_validation_runs")

    op.drop_index("ix_nmp_lifecycle_next_due", table_name="network_monitoring_policies")
    op.drop_index("ix_nmp_org_target", table_name="network_monitoring_policies")
    op.drop_index("ix_nmp_org_lifecycle", table_name="network_monitoring_policies")
    op.drop_table("network_monitoring_policies")
