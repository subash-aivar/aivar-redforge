"""SQLAlchemy ORM models for evaluation context."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import Boolean, DateTime, Float, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID


class EvaluationBase(DeclarativeBase):
    pass


class CampaignEvaluationModel(EvaluationBase):
    __tablename__ = "campaign_evaluations"
    __table_args__ = {"schema": "evaluation"}  # noqa: RUF012

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    campaign_instance_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), nullable=False, unique=True, index=True
    )
    campaign_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    run_number: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    composite_outcome: Mapped[str | None] = mapped_column(String(32), nullable=True)
    execution_failed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    correlation_window_minutes: Mapped[int] = mapped_column(Integer, nullable=False)

    objective_specs_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    assessments_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    technique_outcomes_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    late_detections_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    metrics_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    kill_chain_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    compliance_mappings_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class CampaignMetricsSnapshotModel(EvaluationBase):
    __tablename__ = "campaign_metrics_snapshots"
    __table_args__ = {"schema": "evaluation"}  # noqa: RUF012

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    campaign_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    run_number: Mapped[int] = mapped_column(Integer, nullable=False)
    snapshot_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    composite_outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    detection_coverage_percent: Mapped[float] = mapped_column(Float, nullable=False)
    technique_success_rate: Mapped[float] = mapped_column(Float, nullable=False)
    evasion_rate: Mapped[float] = mapped_column(Float, nullable=False)
    mean_time_to_detect_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    objectives_achieved_count: Mapped[int] = mapped_column(Integer, nullable=False)
    objectives_failed_count: Mapped[int] = mapped_column(Integer, nullable=False)
    actions_executed_count: Mapped[int] = mapped_column(Integer, nullable=False)
    actions_failed_count: Mapped[int] = mapped_column(Integer, nullable=False)
    campaign_duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    kill_chain_phases_covered_json: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    metrics_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
