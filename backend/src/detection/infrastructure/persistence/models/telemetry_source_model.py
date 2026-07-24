"""SQLAlchemy model for TelemetrySource aggregate (metadata only — no telemetry)."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import JSON, DateTime, Float, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base

_JSONB_PORTABLE = JSON().with_variant(JSONB, "postgresql")


_SCHEMA = "detection"


class TelemetrySourceModel(Base):
    """
    Persistence for TelemetrySource configuration metadata.

    Schema / connection / health stored as _JSONB_PORTABLE metadata — never stores
    telemetry event payloads.
    """

    __tablename__ = "telemetry_sources"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    source_type: Mapped[str] = mapped_column(String(64), nullable=False)
    trust_level: Mapped[str] = mapped_column(String(32), nullable=False)
    lifecycle_state: Mapped[str] = mapped_column(String(32), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Schema metadata
    schema_version: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_json: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)

    # Connection / routing metadata (no credentials)
    connection_json: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)

    # Health metadata
    health_status: Mapped[str] = mapped_column(String(32), nullable=False)
    health_json: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)

    # Latency / retention profiles
    latency_expected_seconds: Mapped[float] = mapped_column(Float, nullable=False)
    latency_max_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    retention_seconds: Mapped[float] = mapped_column(Float, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_telemetry_sources_tenant_name"),
        Index("ix_telemetry_sources_tenant_id", "tenant_id"),
        Index("ix_telemetry_sources_tenant_lifecycle", "tenant_id", "lifecycle_state"),
        Index("ix_telemetry_sources_tenant_type", "tenant_id", "source_type"),
        Index("ix_telemetry_sources_tenant_health", "tenant_id", "health_status"),
        {"schema": _SCHEMA},
    )
