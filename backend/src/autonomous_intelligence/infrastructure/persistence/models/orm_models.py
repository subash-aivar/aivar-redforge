"""ORM models mapping the `autonomous_intelligence` schema (migrations 0131-0135)."""

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


_SCHEMA = "autonomous_intelligence"


class OptimizationModelModel(Base):
    __tablename__ = "optimization_models"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    target_type: Mapped[str] = mapped_column(String(80), nullable=False)
    model_version: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    accuracy_metrics: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    conformity_assessment_ref: Mapped[str | None] = mapped_column(Text, nullable=True)
    feedback_sample_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    retraining_threshold: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    deployed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class IntelligenceSuggestionModel(Base):
    __tablename__ = "intelligence_suggestions"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    target_type: Mapped[str] = mapped_column(String(80), nullable=False)
    target_context: Mapped[str] = mapped_column(String(80), nullable=False)
    target_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    status: Mapped[str] = mapped_column(String(40), nullable=False)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False)
    model_id: Mapped[str] = mapped_column(String(128), nullable=False)
    model_version: Mapped[int] = mapped_column(Integer, nullable=False)
    rationale_summary: Mapped[str] = mapped_column(Text, nullable=False)
    supporting_signal_refs: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    proposed_change_payload: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    priority: Mapped[str] = mapped_column(String(20), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    review_deadline_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_by: Mapped[str | None] = mapped_column(Text, nullable=True)
    rejected_by: Mapped[str | None] = mapped_column(Text, nullable=True)
    rejection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class SuggestionOutcomeModel(Base):
    __tablename__ = "suggestion_outcomes"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    suggestion_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    target_type: Mapped[str] = mapped_column(String(80), nullable=False)
    outcome_type: Mapped[str] = mapped_column(String(40), nullable=False)
    measurement_window_days: Mapped[int] = mapped_column(Integer, nullable=False)
    baseline_metric: Mapped[float] = mapped_column(Float, nullable=False)
    observed_metric: Mapped[float | None] = mapped_column(Float, nullable=True)
    delta: Mapped[float | None] = mapped_column(Float, nullable=True)
    measured_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AutonomousOperationsPolicyModel(Base):
    __tablename__ = "autonomous_operations_policies"
    __table_args__ = ({"schema": _SCHEMA},)

    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    kill_switch_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    review_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    min_confidence_by_type: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    enabled_target_types: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
