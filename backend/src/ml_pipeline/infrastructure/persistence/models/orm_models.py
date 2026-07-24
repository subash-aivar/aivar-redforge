"""ORM models mapping the `ml_pipeline` schema (migrations 0096-0098)."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import JSON, Boolean, DateTime, Float, Integer, LargeBinary, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base

_JSONB_PORTABLE = JSON().with_variant(JSONB, "postgresql")


_SCHEMA = "ml_pipeline"


class MLModelModel(Base):
    __tablename__ = "ml_models"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    model_type: Mapped[str] = mapped_column(String(64), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    dataset_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    accuracy_metrics_json: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    artifact_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    trained_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deployed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deprecated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_drift_check_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    psi_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    governance_history_json: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)


class MLModelArtifactModel(Base):
    __tablename__ = "ml_model_artifacts"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    model_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    artifact_bytes: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    byte_size: Mapped[int] = mapped_column(Integer, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class PredictiveRiskSignalModel(Base):
    __tablename__ = "predictive_risk_signals"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    model_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    asset_ref_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    signal_type: Mapped[str] = mapped_column(String(64), nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    features_json: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
