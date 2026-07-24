"""ORM models mapping the `threat_hunt` schema (migrations 0143-0147)."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import JSON, DateTime, Float, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base

_JSONB_PORTABLE = JSON().with_variant(JSONB, "postgresql")


_SCHEMA = "threat_hunt"


class ThreatHuntCandidateModel(Base):
    __tablename__ = "threat_hunt_candidates"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    detection_logic_draft: Mapped[str] = mapped_column(Text, nullable=False)
    detection_rule_format: Mapped[str] = mapped_column(String(20), nullable=False)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False)
    candidate_status: Mapped[str] = mapped_column(String(30), nullable=False)
    promoted_rule_version_id: Mapped[UUID | None] = mapped_column(
        PgUUID(as_uuid=True), nullable=True
    )
    review_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reviewed_by: Mapped[str | None] = mapped_column(Text, nullable=True)


class ThreatHuntAnomalySignalRefModel(Base):
    __tablename__ = "threat_hunt_anomaly_signal_refs"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    candidate_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    signal_id: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(80), nullable=False)


class ThreatHuntTechniqueRefModel(Base):
    __tablename__ = "threat_hunt_technique_refs"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    candidate_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    technique_id: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)


class ThreatHuntConfigurationModel(Base):
    __tablename__ = "threat_hunt_configurations"
    __table_args__ = ({"schema": _SCHEMA},)

    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    min_signal_strength: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    enabled_signal_types: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
