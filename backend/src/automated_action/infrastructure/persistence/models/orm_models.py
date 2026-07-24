"""ORM models mapping the `automated_action` schema (migrations 0120-0122, 0151)."""

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


_SCHEMA = "automated_action"


class AutomationExecutionModel(Base):
    __tablename__ = "automation_executions"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    playbook_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    playbook_version: Mapped[int] = mapped_column(Integer, nullable=False)
    playbook_content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    trigger_source_context: Mapped[str] = mapped_column(String(40), nullable=False)
    trigger_source_event_type: Mapped[str] = mapped_column(Text, nullable=False, default="")
    source_event_id: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False)
    operator_id: Mapped[str] = mapped_column(Text, nullable=False)
    current_step: Mapped[int] = mapped_column(Integer, nullable=False)
    total_steps: Mapped[int] = mapped_column(Integer, nullable=False)
    max_impact_level: Mapped[str] = mapped_column(String(20), nullable=False)
    escalation_request: Mapped[dict[str, Any] | None] = mapped_column(
        _JSONB_PORTABLE, nullable=True,
    )
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class AutomatedActionRecordModel(Base):
    __tablename__ = "automated_action_records"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    execution_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    step_number: Mapped[int] = mapped_column(Integer, nullable=False)
    action_type: Mapped[str] = mapped_column(Text, nullable=False)
    connector_type: Mapped[str] = mapped_column(String(50), nullable=False)
    target_resource: Mapped[str] = mapped_column(Text, nullable=False)
    parameters_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    outcome: Mapped[str | None] = mapped_column(String(20), nullable=True)
    external_reference: Mapped[str | None] = mapped_column(Text, nullable=True)
    failure_mode: Mapped[str | None] = mapped_column(String(40), nullable=True)
    attempted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rollback_available: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    rollback_parameters_ref: Mapped[str | None] = mapped_column(Text, nullable=True)


class RollbackRecordModel(Base):
    __tablename__ = "rollback_records"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    original_record_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    execution_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    rollback_status: Mapped[str] = mapped_column(String(30), nullable=False)
    initiated_by: Mapped[str] = mapped_column(Text, nullable=False)
    initiated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
