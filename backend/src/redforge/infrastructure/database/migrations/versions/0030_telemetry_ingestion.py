"""Customer-owned security telemetry ingestion — M18 remaining gaps.

Two tables:

  telemetry_sensors — registered sensor/source identities. An admin
  registers a sensor with a name and format type before telemetry can
  be ingested for it. Supplies an opaque ingestion token reference
  (never a raw secret) used for authenticated ingestion.

  telemetry_events — normalized security events ingested from Suricata
  EVE JSON, Zeek JSON logs, or structured syslog. One row per
  (org, sensor, source_event_id) — source_event_id is the
  deduplication key (Suricata's flow_id / Zeek's uid / a hash of
  the normalized fields where no native ID exists). Idempotent: a
  re-ingested event with the same source_event_id updates in place
  rather than creating a duplicate.

  The `bytes_in`/`bytes_out`/`packets` fields are only populated for
  event types that genuinely carry traffic metrics (Suricata netflow,
  Zeek conn). Absent for alert-only event types.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0030"
down_revision: str = "0029"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "telemetry_sensors",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("format", sa.String(40), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        # Token reference (e.g. env-var name or vault path) — never the raw token
        sa.Column("token_ref", sa.String(200), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, default=True),
        sa.Column("created_by", sa.String(26), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("id", "organization_id", name="ux_ts_id_org"),
        sa.UniqueConstraint("organization_id", "name", name="ux_ts_org_name"),
    )
    op.create_index("ix_ts_org", "telemetry_sensors", ["organization_id"])

    op.create_table(
        "telemetry_events",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("sensor_id", sa.String(26), nullable=False),
        # Source-assigned event ID (Suricata flow_id, Zeek uid, etc.)
        # or a deterministic hash of normalized fields if source has none.
        sa.Column("source_event_id", sa.String(256), nullable=False),
        sa.Column("format", sa.String(40), nullable=False),
        sa.Column("event_type", sa.String(80), nullable=False),
        sa.Column("event_ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("src_ip", sa.String(45), nullable=True),
        sa.Column("dst_ip", sa.String(45), nullable=True),
        sa.Column("src_port", sa.Integer(), nullable=True),
        sa.Column("dst_port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(20), nullable=True),
        sa.Column("action", sa.String(40), nullable=True),
        sa.Column("severity", sa.String(20), nullable=True),
        sa.Column("signature", sa.String(512), nullable=True),
        sa.Column("signature_id", sa.String(40), nullable=True),
        sa.Column("bytes_in", sa.BigInteger(), nullable=True),
        sa.Column("bytes_out", sa.BigInteger(), nullable=True),
        sa.Column("packets_in", sa.BigInteger(), nullable=True),
        sa.Column("packets_out", sa.BigInteger(), nullable=True),
        # Enrichment state: 'pending' → awaiting public-IP enrichment;
        # 'done' → enrichment attempted; 'skipped' → private IPs only
        sa.Column("enrichment_state", sa.String(20), nullable=False, default="pending"),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["sensor_id", "organization_id"],
            ["telemetry_sensors.id", "telemetry_sensors.organization_id"],
            name="fk_te_same_tenant_sensor",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("id", "organization_id", name="ux_te_id_org"),
        sa.UniqueConstraint(
            "organization_id", "sensor_id", "source_event_id", name="ux_te_dedup"
        ),
    )
    op.create_index("ix_te_org_ts", "telemetry_events", ["organization_id", "event_ts"])
    op.create_index("ix_te_org_sensor", "telemetry_events", ["organization_id", "sensor_id"])
    op.create_index(
        "ix_te_org_enrich", "telemetry_events", ["organization_id", "enrichment_state"]
    )


def downgrade() -> None:
    op.drop_index("ix_te_org_enrich", table_name="telemetry_events")
    op.drop_index("ix_te_org_sensor", table_name="telemetry_events")
    op.drop_index("ix_te_org_ts", table_name="telemetry_events")
    op.drop_table("telemetry_events")
    op.drop_index("ix_ts_org", table_name="telemetry_sensors")
    op.drop_table("telemetry_sensors")
