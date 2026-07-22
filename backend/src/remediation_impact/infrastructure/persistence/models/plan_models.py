"""SQLAlchemy models for remediation_impact schema (Phase 4)."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import DateTime, Float, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base


class ExposureReductionPlanModel(Base):
    __tablename__ = "exposure_reduction_plans"
    __table_args__ = ({"schema": "remediation_impact"},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    committed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    committed_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    projected_exposure_reduction: Mapped[float] = mapped_column(Float, nullable=False)
    estimated_business_impact: Mapped[float] = mapped_column(Float, nullable=False)
    algorithm: Mapped[str] = mapped_column(String(64), nullable=False)
    top_k: Mapped[int] = mapped_column(Integer, nullable=False)
    sample_size: Mapped[int] = mapped_column(Integer, nullable=False)
    approximation_mode: Mapped[str] = mapped_column(String(64), nullable=False)
    simulation_seed: Mapped[int] = mapped_column(Integer, nullable=False)
    score_input_version: Mapped[int] = mapped_column(Integer, nullable=False)
    plan_steps_json: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
