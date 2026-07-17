"""SQLAlchemy ORM models for the Compliance bounded context (Phase 1 — catalog only)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base


class ComplianceFrameworkModel(Base):
    """Persists FrameworkDefinition (status + metadata)."""

    __tablename__ = "compliance_frameworks"
    __table_args__ = (
        UniqueConstraint("key", name="uq_cf_key"),
        Index("ix_cf_status", "status"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    key: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="draft")
    # FrameworkMetadata serialised as JSONB
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ComplianceRequirementModel(Base):
    """Persists ControlRequirement rows, keyed by framework."""

    __tablename__ = "compliance_requirements"
    __table_args__ = (
        UniqueConstraint("framework_key", "requirement_ref", name="uq_cr_fw_ref"),
        Index("ix_cr_framework_key", "framework_key"),
        Index("ix_cr_domain", "domain"),
        Index("ix_cr_severity", "severity"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    framework_key: Mapped[str] = mapped_column(String(80), nullable=False)
    requirement_ref: Mapped[str] = mapped_column(String(80), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    domain: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    guidance: Mapped[str] = mapped_column(Text, nullable=False, default="")
    policy_threshold: Mapped[int] = mapped_column(Integer, nullable=False, default=80)
    tags: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False, default=list)
    external_ref: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ComplianceMappingModel(Base):
    """Persists ControlMapping cross-framework relationships."""

    __tablename__ = "compliance_mappings"
    __table_args__ = (
        UniqueConstraint(
            "source_requirement_id",
            "target_requirement_id",
            "is_active",
            name="uq_cm_src_tgt_active",
        ),
        Index("ix_cm_source_fw", "source_framework_key"),
        Index("ix_cm_target_fw", "target_framework_key"),
        Index("ix_cm_is_active", "is_active"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    source_requirement_id: Mapped[str] = mapped_column(String(26), nullable=False)
    target_requirement_id: Mapped[str] = mapped_column(String(26), nullable=False)
    source_framework_key: Mapped[str] = mapped_column(String(80), nullable=False)
    target_framework_key: Mapped[str] = mapped_column(String(80), nullable=False)
    confidence: Mapped[str] = mapped_column(String(20), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False, default="")
    version: Mapped[str] = mapped_column(String(20), nullable=False, default="1.0")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
