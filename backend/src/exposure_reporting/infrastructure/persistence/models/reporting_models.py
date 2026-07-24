"""SQLAlchemy models for exposure_reporting schema (Phase 5)."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import JSON, DateTime, Float, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base

_JSONB_PORTABLE = JSON().with_variant(JSONB, "postgresql")



class ExposureReportModel(Base):
    __tablename__ = "exposure_reports"
    __table_args__ = ({"schema": "exposure_reporting"},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False, index=True)
    report_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    template_id: Mapped[str] = mapped_column(String(128), nullable=False)
    narrative: Mapped[str] = mapped_column(Text, nullable=False)
    content_json: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    generated_by: Mapped[str] = mapped_column(String(256), nullable=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    time_range_start: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    time_range_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class BusinessImpactMappingModel(Base):
    __tablename__ = "business_impact_mappings"
    __table_args__ = (
        UniqueConstraint("tenant_id", "asset_ref_id", name="uq_bim_tenant_asset"),
        {"schema": "exposure_reporting"},
    )

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False, index=True)
    asset_ref_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    criticality: Mapped[str] = mapped_column(String(64), nullable=False)
    impact_domain: Mapped[str] = mapped_column(String(64), nullable=False)
    authored_by: Mapped[str] = mapped_column(String(256), nullable=False)
    business_process_ref: Mapped[str | None] = mapped_column(String(256), nullable=True)
    business_unit_ref: Mapped[str | None] = mapped_column(String(256), nullable=True)
    financial_impact_estimate: Mapped[float | None] = mapped_column(Float, nullable=True)
    regulatory_scope_json: Mapped[list[Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=list,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ExposureKpiProjectionModel(Base):
    __tablename__ = "exposure_kpi_projections"
    __table_args__ = ({"schema": "exposure_reporting"},)

    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    kpi_json: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ExposureTrendProjectionModel(Base):
    __tablename__ = "exposure_trend_projections"
    __table_args__ = ({"schema": "exposure_reporting"},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False, index=True)
    tenant_exposure_score: Mapped[float] = mapped_column(Float, nullable=False)
    asset_count: Mapped[int] = mapped_column(Integer, nullable=False)
    score_input_version: Mapped[str] = mapped_column(String(64), nullable=False)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
