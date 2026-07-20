"""SQLAlchemy models for DetectionExecution and DetectionFinding."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import DateTime, Index, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base

_SCHEMA = "detection"


class DetectionExecutionModel(Base):
    __tablename__ = "detection_executions"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    source_id: Mapped[str] = mapped_column(String(64), nullable=False)
    source_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    trigger: Mapped[str] = mapped_column(String(32), nullable=False)
    stats_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    error_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    finding_refs_json: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    scheduled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (
        Index("ix_detection_executions_tenant_id", "tenant_id"),
        Index("ix_detection_executions_tenant_state", "tenant_id", "state"),
        Index("ix_detection_executions_tenant_rule", "tenant_id", "rule_id"),
        Index("ix_detection_executions_tenant_started", "tenant_id", "started_at"),
        Index("ix_detection_executions_tenant_scheduled", "tenant_id", "scheduled_at"),
        {"schema": _SCHEMA},
    )


class DetectionFindingModel(Base):
    __tablename__ = "detection_findings"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    finding_key: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    execution_id: Mapped[str] = mapped_column(String(64), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(256), nullable=False)
    asset_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    signal_id: Mapped[str] = mapped_column(String(256), nullable=False)
    signal_source_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    telemetry_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    state: Mapped[str] = mapped_column(String(48), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    mitre_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    correlation_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    analyst_note_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    escalation_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    reopened_from: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (
        Index("ix_detection_findings_tenant_id", "tenant_id"),
        Index("ix_detection_findings_tenant_key", "tenant_id", "finding_key"),
        Index("ix_detection_findings_tenant_state", "tenant_id", "state"),
        Index("ix_detection_findings_tenant_asset", "tenant_id", "asset_id"),
        Index("ix_detection_findings_tenant_rule", "tenant_id", "rule_id"),
        Index("ix_detection_findings_tenant_detected", "tenant_id", "detected_at"),
        Index("ix_detection_findings_tenant_last_seen", "tenant_id", "last_seen_at"),
        {"schema": _SCHEMA},
    )
