"""ORM models mapping the `reporting` schema (migrations 0094-0095)."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import JSON, Boolean, DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base

_JSONB_PORTABLE = JSON().with_variant(JSONB, "postgresql")


_SCHEMA = "reporting"


class ReportTemplateModel(Base):
    __tablename__ = "report_templates"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    report_type: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    sections_json: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    is_platform: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ScheduledReportModel(Base):
    __tablename__ = "scheduled_reports"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    template_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    schedule_cron: Mapped[str] = mapped_column(String(64), nullable=False)
    parameters_json: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    recipients_json: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_invocation_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # Not a migration column — cadence_minutes is domain state with no
    # dedicated column (schedule_cron is the display string; the aggregate
    # separately tracks minutes for next_run_at advancement). Packed into
    # parameters_json under a reserved key rather than losing it silently.


class ReportInstanceModel(Base):
    __tablename__ = "report_instances"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    template_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    scheduled_report_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    report_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    artifact_json: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    narrative: Mapped[str] = mapped_column(Text, nullable=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    generated_by: Mapped[str] = mapped_column(String(256), nullable=False)
