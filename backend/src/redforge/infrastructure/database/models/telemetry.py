"""ORM models for the Customer-owned Telemetry Ingestion bounded context
(M18 remaining gaps). Two tables: telemetry_sensors (registered sources)
and telemetry_events (normalized, deduplicated security events)."""

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base


class TelemetrySensorModel(Base):
    __tablename__ = "telemetry_sensors"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="ux_ts_id_org"),
        UniqueConstraint("organization_id", "name", name="ux_ts_org_name"),
        Index("ix_ts_org", "organization_id"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    format: Mapped[str] = mapped_column(String(40), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    token_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by: Mapped[str] = mapped_column(String(26), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class TelemetryEventModel(Base):
    __tablename__ = "telemetry_events"
    __table_args__ = (
        ForeignKeyConstraint(
            ["sensor_id", "organization_id"],
            ["telemetry_sensors.id", "telemetry_sensors.organization_id"],
            name="fk_te_same_tenant_sensor",
            ondelete="CASCADE",
        ),
        UniqueConstraint("id", "organization_id", name="ux_te_id_org"),
        UniqueConstraint("organization_id", "sensor_id", "source_event_id", name="ux_te_dedup"),
        Index("ix_te_org_ts", "organization_id", "event_ts"),
        Index("ix_te_org_sensor", "organization_id", "sensor_id"),
        Index("ix_te_org_enrich", "organization_id", "enrichment_state"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    sensor_id: Mapped[str] = mapped_column(String(26), nullable=False)
    source_event_id: Mapped[str] = mapped_column(String(256), nullable=False)
    format: Mapped[str] = mapped_column(String(40), nullable=False)
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    event_ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    src_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(20), nullable=True)
    action: Mapped[str | None] = mapped_column(String(40), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    signature: Mapped[str | None] = mapped_column(String(512), nullable=True)
    signature_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    bytes_in: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    bytes_out: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    packets_in: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    packets_out: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    enrichment_state: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
