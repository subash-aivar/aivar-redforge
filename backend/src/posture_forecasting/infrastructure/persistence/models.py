"""ORM models mapping the `posture_forecasting` schema (migrations 0138-0142)."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import JSON, DateTime, Float, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base

_JSONB_PORTABLE = JSON().with_variant(JSONB, "postgresql")


_SCHEMA = "posture_forecasting"


class PostureForecastModel(Base):
    __tablename__ = "posture_forecasts"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    predicted_30d: Mapped[float] = mapped_column(Float, nullable=False)
    predicted_60d: Mapped[float] = mapped_column(Float, nullable=False)
    predicted_90d: Mapped[float] = mapped_column(Float, nullable=False)
    model_id: Mapped[str] = mapped_column(String(128), nullable=False)
    model_version: Mapped[int] = mapped_column(Integer, nullable=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ForecastAccuracyRecordModel(Base):
    __tablename__ = "forecast_accuracy_records"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    forecast_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    horizon_days: Mapped[int] = mapped_column(Integer, nullable=False)
    actual_score: Mapped[float] = mapped_column(Float, nullable=False)
    predicted_score: Mapped[float] = mapped_column(Float, nullable=False)
    absolute_error: Mapped[float] = mapped_column(Float, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ForecastConfigurationModel(Base):
    __tablename__ = "forecast_configurations"
    __table_args__ = ({"schema": _SCHEMA},)

    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    forecast_frequency_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=24)
    signal_weights: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)


class ForecastInputSnapshotModel(Base):
    __tablename__ = "forecast_input_snapshots"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    forecast_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    baseline_exposure_score: Mapped[float] = mapped_column(Float, nullable=False)
    remediation_velocity_per_day: Mapped[float] = mapped_column(Float, nullable=False)
    open_critical_count: Mapped[int] = mapped_column(Integer, nullable=False)
    open_high_count: Mapped[int] = mapped_column(Integer, nullable=False)
    snapshot_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
