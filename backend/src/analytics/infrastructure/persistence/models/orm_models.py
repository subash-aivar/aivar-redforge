"""ORM models mapping the `analytics` schema (migrations 0091, 0093).

Two small aggregate/schema mismatches, handled without a new migration
since neither loses real domain state:
- AnalyticsDataSet.projection_checkpoint maps to the column
  checkpoint_event_id (name differs, same meaning).
- AnalyticsQuery.updated_at has no column — the aggregate never mutates it
  after create() (no method in analytics_query.py touches it), so it's
  reconstructed as equal to created_at on load rather than adding a column
  for a field that can never actually change. analytics_queries.status has
  no aggregate field — written as a constant, matching the aggregate's own
  disinterest in it.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import JSON, Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base

_JSONB_PORTABLE = JSON().with_variant(JSONB, "postgresql")


_SCHEMA = "analytics"


class AnalyticsDataSetModel(Base):
    __tablename__ = "analytics_datasets"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    domain: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    checkpoint_event_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    records_ingested: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class SecurityKPIModel(Base):
    __tablename__ = "security_kpis"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    kpi_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False)
    computation_schedule_cron: Mapped[str] = mapped_column(String(64), nullable=False)
    latest_value: Mapped[float | None] = mapped_column(Float, nullable=True)
    latest_unit: Mapped[str | None] = mapped_column(String(64), nullable=True)
    definition_version: Mapped[int] = mapped_column(Integer, nullable=False)
    last_computed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AnomalyDetectionBaselineModel(Base):
    __tablename__ = "anomaly_detection_baselines"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    signal_type: Mapped[str] = mapped_column(String(64), nullable=False)
    method: Mapped[str] = mapped_column(String(64), nullable=False)
    window_days: Mapped[int] = mapped_column(Integer, nullable=False)
    bootstrapped: Mapped[bool] = mapped_column(Boolean, nullable=False)
    observation_count: Mapped[int] = mapped_column(Integer, nullable=False)
    params_json: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AnalyticsQueryModel(Base):
    __tablename__ = "analytics_queries"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    template: Mapped[str] = mapped_column(Text, nullable=False)
    domain: Mapped[str] = mapped_column(String(64), nullable=False)
    parameters_json: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    created_by: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="ACTIVE")
