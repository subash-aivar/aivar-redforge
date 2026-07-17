"""SQLAlchemy ORM models for the Attack Path Engine — M22 Phase 5 (migration 0038)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base


class AttackPathModel(Base):
    __tablename__ = "attack_paths"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    root_entity_id: Mapped[str] = mapped_column(String(26), nullable=False)
    root_canonical_key: Mapped[str] = mapped_column(String(300), nullable=False)
    terminal_entity_id: Mapped[str | None] = mapped_column(String(26), nullable=True)
    path_confidence: Mapped[str] = mapped_column(String(20), nullable=False)
    technique_coverage: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)
    attributed_actors: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)
    step_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    evidence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_exposure_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    first_step_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_step_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    investigation_id: Mapped[str | None] = mapped_column(String(26), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AttackPathStepModel(Base):
    __tablename__ = "attack_path_steps"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    attack_path_id: Mapped[str] = mapped_column(
        String(26), ForeignKey("attack_paths.id", ondelete="CASCADE"), nullable=False
    )
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    entity_id: Mapped[str] = mapped_column(String(26), nullable=False)
    canonical_key: Mapped[str] = mapped_column(String(300), nullable=False)
    step_type: Mapped[str] = mapped_column(String(20), nullable=False)
    confidence: Mapped[str] = mapped_column(String(20), nullable=False)
    technique_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    relationship_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    kill_chain_phase: Mapped[str | None] = mapped_column(String(64), nullable=True)
    observed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    inferred_from_step: Mapped[int | None] = mapped_column(Integer, nullable=True)
    exposure_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)


class AttackPathStepEvidenceModel(Base):
    __tablename__ = "attack_path_step_evidence"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    step_id: Mapped[str] = mapped_column(
        String(26), ForeignKey("attack_path_steps.id", ondelete="CASCADE"), nullable=False
    )
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    evidence_ref: Mapped[str] = mapped_column(String(128), nullable=False)
