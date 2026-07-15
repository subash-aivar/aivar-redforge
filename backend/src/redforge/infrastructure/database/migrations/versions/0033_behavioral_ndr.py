"""Behavioral Security NDR domain — M20.

Creates four tables:
  behavior_entity_baselines   — per-entity rolling baseline statistics
  behavior_observations       — time-window aggregation snapshots
  behavior_detections         — active detection lifecycle records
  behavior_detection_events   — detection timeline entries

The partial unique index on behavior_detections enforces exactly one active
detection per (organization_id, correlation_key) while status is not terminal,
matching the DDoS advisory-lock + partial-index pattern from M19.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0033"
down_revision: str = "0032"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_OPEN_STATES = "('DETECTED', 'ACTIVE', 'INVESTIGATING', 'MONITORING')"
_ACTIVE_INDEX = "ux_bd_org_corr_active"


def upgrade() -> None:
    # behavior_entity_baselines
    op.create_table(
        "behavior_entity_baselines",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("entity_type", sa.String(40), nullable=False),
        sa.Column("entity_id", sa.String(200), nullable=False),
        sa.Column("baseline_confidence", sa.String(30), nullable=False),
        sa.Column("window_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("p75_unique_dst_ips", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("p75_bytes_out", sa.Float, nullable=True),
        sa.Column("p75_event_count", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("seen_dst_ips", sa.JSON, nullable=True),
        sa.Column("seen_service_pairs", sa.JSON, nullable=True),
        sa.Column("seen_east_west_pairs", sa.JSON, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_unique_constraint(
        "ux_beb_org_entity",
        "behavior_entity_baselines",
        ["organization_id", "entity_type", "entity_id"],
    )
    op.create_index("ix_beb_org", "behavior_entity_baselines", ["organization_id"])
    op.create_index("ix_beb_org_updated", "behavior_entity_baselines",
                    ["organization_id", "updated_at"])

    # behavior_observations
    op.create_table(
        "behavior_observations",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("entity_id", sa.String(200), nullable=False),
        sa.Column("entity_type", sa.String(40), nullable=False),
        sa.Column("window_start_ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end_ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_seconds", sa.Integer, nullable=False),
        sa.Column("event_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("unique_dst_ips", sa.Integer, nullable=False, server_default="0"),
        sa.Column("unique_dst_ports", sa.Integer, nullable=False, server_default="0"),
        sa.Column("total_bytes_out", sa.BigInteger, nullable=True),
        sa.Column("total_bytes_in", sa.BigInteger, nullable=True),
        sa.Column("dst_ips_seen", sa.JSON, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_unique_constraint(
        "ux_bo_org_entity_window",
        "behavior_observations",
        ["organization_id", "entity_id", "window_start_ts"],
    )
    op.create_index("ix_bo_org_entity", "behavior_observations",
                    ["organization_id", "entity_id"])
    op.create_index("ix_bo_org_ts", "behavior_observations",
                    ["organization_id", "window_start_ts"])

    # behavior_detections
    op.create_table(
        "behavior_detections",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("correlation_key", sa.String(400), nullable=False),
        sa.Column("entity_type", sa.String(40), nullable=False),
        sa.Column("entity_id", sa.String(200), nullable=False),
        sa.Column("detection_type", sa.String(60), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="'DETECTED'"),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("evidence", sa.JSON, nullable=True),
        sa.Column("secondary_entity_id", sa.String(200), nullable=True),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("quiet_windows", sa.Integer, nullable=False, server_default="0"),
        sa.Column("observation_count", sa.Integer, nullable=False, server_default="1"),
        sa.Column("assigned_to", sa.String(26), nullable=True),
        sa.Column("notes", sa.Text, nullable=False, server_default="''"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_unique_constraint(
        "ux_bd_id_org",
        "behavior_detections",
        ["id", "organization_id"],
    )
    op.create_index("ix_bd_org_status", "behavior_detections",
                    ["organization_id", "status"])
    op.create_index("ix_bd_org_entity", "behavior_detections",
                    ["organization_id", "entity_id"])
    op.create_index("ix_bd_org_ts", "behavior_detections",
                    ["organization_id", "detected_at"])
    # Partial unique index — one active detection per correlation_key
    op.execute(
        f"""
        CREATE UNIQUE INDEX {_ACTIVE_INDEX}
        ON behavior_detections (organization_id, correlation_key)
        WHERE status IN {_OPEN_STATES}
        """
    )

    # behavior_detection_events
    op.create_table(
        "behavior_detection_events",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("detection_id", sa.String(26), nullable=False),
        sa.Column("event_type", sa.String(60), nullable=False),
        sa.Column("detail", sa.Text, nullable=False, server_default="''"),
        sa.Column("actor_user_id", sa.String(26), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_bde_detection", "behavior_detection_events", ["detection_id"])
    op.create_index("ix_bde_org_ts", "behavior_detection_events",
                    ["organization_id", "created_at"])


def downgrade() -> None:
    op.execute(f"DROP INDEX IF EXISTS {_ACTIVE_INDEX}")
    op.drop_table("behavior_detection_events")
    op.drop_table("behavior_detections")
    op.drop_table("behavior_observations")
    op.drop_table("behavior_entity_baselines")
