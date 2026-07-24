"""ORM models for M22 Phase 6 sync / investigation-path debounce state."""

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base

_JSONB_PORTABLE = JSON().with_variant(JSONB, "postgresql")



class ThreatIntelSyncStateModel(Base):
    __tablename__ = "threat_intel_sync_state"

    job_key: Mapped[str] = mapped_column(String(40), primary_key=True)
    last_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_status: Mapped[str] = mapped_column(String(20), nullable=False, default="idle")
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_result: Mapped[dict[str, Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=dict,
    )
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class InvestigationPathComputeStateModel(Base):
    __tablename__ = "investigation_path_compute_state"

    organization_id: Mapped[str] = mapped_column(String(26), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(String(26), primary_key=True)
    last_compute_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    pending_evidence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
