"""DDoS Detection & Defense Center — M19.

Six tables for the complete DDoS detection, correlation, and mitigation
architecture. All tables are tenant-scoped via organization_id; no
cross-tenant foreign keys exist (composite FK pattern established in M18).

Tables:
  ddos_protected_resources    — explicit monitoring targets
  ddos_detection_policies     — per-resource detection configuration
  ddos_observation_windows    — persisted traffic aggregation snapshots
  ddos_incidents              — correlated attack lifecycle (with version
                                column for optimistic-concurrency control)
  ddos_incident_events        — immutable incident timeline (append-only)
  ddos_mitigation_recommendations — human-approval-gated mitigation proposals

Detection is event-time based (against telemetry_events.event_ts) rather
than ingestion-time, consistent with the M18 bandwidth read models.

Down migration: drops in reverse dependency order.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0031"
down_revision: str = "0030"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    # ── ddos_protected_resources ─────────────────────────────────────────
    op.create_table(
        "ddos_protected_resources",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        # scope_type: "cidr" | "asset" | "any"
        sa.Column("scope_type", sa.String(20), nullable=False),
        # scope_value: CIDR string, asset id, or None
        sa.Column("scope_value", sa.String(200), nullable=True),
        sa.Column("criticality", sa.String(20), nullable=False, server_default="MEDIUM"),
        sa.Column("monitored_ports", sa.JSON(), nullable=True),
        sa.Column("monitoring_enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_by", sa.String(26), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("id", "organization_id", name="ux_dpr_id_org"),
        sa.UniqueConstraint("organization_id", "name", name="ux_dpr_org_name"),
    )
    op.create_index("ix_dpr_org", "ddos_protected_resources", ["organization_id"])

    # ── ddos_detection_policies ──────────────────────────────────────────
    op.create_table(
        "ddos_detection_policies",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("resource_id", sa.String(26), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("profile", sa.String(20), nullable=False, server_default="BALANCED"),
        sa.Column("static_bps_threshold", sa.Float(), nullable=True),
        sa.Column("static_pps_threshold", sa.Float(), nullable=True),
        sa.Column("static_fps_threshold", sa.Float(), nullable=True),
        sa.Column("window_seconds", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("min_breach_windows", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("quiet_period_windows", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("mitigation_mode", sa.String(20), nullable=False, server_default="RECOMMEND_ONLY"),  # noqa: E501
        sa.Column("suppression_windows", sa.JSON(), nullable=True),
        sa.Column("created_by", sa.String(26), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["resource_id", "organization_id"],
            ["ddos_protected_resources.id", "ddos_protected_resources.organization_id"],
            name="fk_ddp_same_tenant_resource",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("id", "organization_id", name="ux_ddp_id_org"),
        sa.UniqueConstraint("organization_id", "resource_id", name="ux_ddp_org_resource"),
    )
    op.create_index("ix_ddp_org", "ddos_detection_policies", ["organization_id"])

    # ── ddos_observation_windows ─────────────────────────────────────────
    op.create_table(
        "ddos_observation_windows",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("resource_id", sa.String(26), nullable=False),
        sa.Column("window_start_ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end_ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_seconds", sa.Integer(), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_bytes_in", sa.BigInteger(), nullable=True),
        sa.Column("total_bytes_out", sa.BigInteger(), nullable=True),
        sa.Column("total_packets_in", sa.BigInteger(), nullable=True),
        sa.Column("total_packets_out", sa.BigInteger(), nullable=True),
        sa.Column("unique_src_ips", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("unique_dst_ports", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("protocol_counts", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("alert_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("syn_pattern_alert_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("detection_fired", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("severity", sa.String(20), nullable=True),
        sa.Column("classification", sa.String(60), nullable=True),
        sa.Column("matched_signals", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("incident_id", sa.String(26), nullable=True),
        sa.Column("computed_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("id", "organization_id", name="ux_dow_id_org"),
        sa.UniqueConstraint(
            "organization_id", "resource_id", "window_start_ts",
            name="ux_dow_org_resource_window",
        ),
    )
    op.create_index(
        "ix_dow_org_resource_ts",
        "ddos_observation_windows",
        ["organization_id", "resource_id", "window_start_ts"],
    )
    op.create_index(
        "ix_dow_org_ts",
        "ddos_observation_windows",
        ["organization_id", "window_start_ts"],
    )

    # ── ddos_incidents ────────────────────────────────────────────────────
    op.create_table(
        "ddos_incidents",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("resource_id", sa.String(26), nullable=False),
        sa.Column("resource_name", sa.String(200), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="DETECTED"),
        sa.Column("severity", sa.String(20), nullable=False, server_default="LOW"),
        sa.Column(
            "classification", sa.String(60), nullable=False,
            server_default="UNCLASSIFIED_DDOS_SUSPECTED",
        ),
        sa.Column("first_detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("peak_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("peak_bytes_per_second", sa.Float(), nullable=True),
        sa.Column("peak_packets_per_second", sa.Float(), nullable=True),
        sa.Column("peak_flows_per_second", sa.Float(), nullable=True),
        sa.Column("peak_unique_src_ips", sa.Integer(), nullable=True),
        sa.Column("peak_deviation_multiplier", sa.Float(), nullable=True),
        sa.Column("opening_evidence", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("latest_evidence", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("consecutive_quiet_windows", sa.Integer(), nullable=False, server_default="0"),
        # Optimistic concurrency: incremented on every status transition
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint("id", "organization_id", name="ux_di_id_org"),
    )
    op.create_index("ix_di_org_status", "ddos_incidents", ["organization_id", "status"])
    op.create_index("ix_di_org_resource", "ddos_incidents", ["organization_id", "resource_id"])
    op.create_index(
        "ix_di_org_detected", "ddos_incidents", ["organization_id", "first_detected_at"]
    )

    # ── ddos_incident_events ──────────────────────────────────────────────
    op.create_table(
        "ddos_incident_events",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("incident_id", sa.String(26), nullable=False),
        sa.Column("event_type", sa.String(60), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("payload", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("actor_id", sa.String(26), nullable=True),
    )
    op.create_index("ix_die_incident", "ddos_incident_events", ["incident_id"])
    op.create_index(
        "ix_die_org_ts", "ddos_incident_events", ["organization_id", "occurred_at"]
    )

    # ── ddos_mitigation_recommendations ──────────────────────────────────
    op.create_table(
        "ddos_mitigation_recommendations",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("incident_id", sa.String(26), nullable=False),
        sa.Column("recommendation_type", sa.String(40), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("recommendation_detail", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("approval_status", sa.String(20), nullable=False, server_default="PENDING"),
        sa.Column("approved_by", sa.String(26), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rejected_by", sa.String(26), nullable=True),
        sa.Column("rejected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rejection_reason", sa.Text(), nullable=True),
        sa.Column("execution_status", sa.String(20), nullable=False, server_default="NOT_STARTED"),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("execution_result", sa.JSON(), nullable=True),
        sa.Column("provider_type", sa.String(40), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("id", "organization_id", name="ux_dmr_id_org"),
    )
    op.create_index(
        "ix_dmr_incident", "ddos_mitigation_recommendations", ["incident_id"]
    )
    op.create_index(
        "ix_dmr_org_status",
        "ddos_mitigation_recommendations",
        ["organization_id", "approval_status"],
    )


def downgrade() -> None:
    op.drop_index("ix_dmr_org_status", table_name="ddos_mitigation_recommendations")
    op.drop_index("ix_dmr_incident", table_name="ddos_mitigation_recommendations")
    op.drop_table("ddos_mitigation_recommendations")

    op.drop_index("ix_die_org_ts", table_name="ddos_incident_events")
    op.drop_index("ix_die_incident", table_name="ddos_incident_events")
    op.drop_table("ddos_incident_events")

    op.drop_index("ix_di_org_detected", table_name="ddos_incidents")
    op.drop_index("ix_di_org_resource", table_name="ddos_incidents")
    op.drop_index("ix_di_org_status", table_name="ddos_incidents")
    op.drop_table("ddos_incidents")

    op.drop_index("ix_dow_org_ts", table_name="ddos_observation_windows")
    op.drop_index("ix_dow_org_resource_ts", table_name="ddos_observation_windows")
    op.drop_table("ddos_observation_windows")

    op.drop_index("ix_ddp_org", table_name="ddos_detection_policies")
    op.drop_table("ddos_detection_policies")

    op.drop_index("ix_dpr_org", table_name="ddos_protected_resources")
    op.drop_table("ddos_protected_resources")
