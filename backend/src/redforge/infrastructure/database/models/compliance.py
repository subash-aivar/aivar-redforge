"""SQLAlchemy ORM models for the Compliance bounded context."""

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


class ComplianceProfileModel(Base):
    __tablename__ = "compliance_profiles"
    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="uq_compliance_profiles_org_name"),
        Index("ix_compliance_profiles_org_status", "organization_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    framework_keys: Mapped[list[str]] = mapped_column(
        ARRAY(String), nullable=False, default=list
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="draft")
    created_by: Mapped[str] = mapped_column(String(26), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AssessmentPeriodModel(Base):
    __tablename__ = "assessment_periods"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "profile_id",
            "name",
            name="uq_assessment_periods_org_profile_name",
        ),
        Index("ix_assessment_periods_org_profile", "organization_id", "profile_id"),
        Index("ix_assessment_periods_org_status", "organization_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    profile_id: Mapped[str] = mapped_column(String(26), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    framework_key: Mapped[str] = mapped_column(String(80), nullable=False)
    period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    period_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="planned")
    created_by: Mapped[str] = mapped_column(String(26), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ControlAssessmentModel(Base):
    __tablename__ = "control_assessments"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "period_id",
            "requirement_id",
            name="uq_control_assessments_org_period_req",
        ),
        Index("ix_control_assessments_org_period", "organization_id", "period_id"),
        Index("ix_control_assessments_org_status", "organization_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    profile_id: Mapped[str] = mapped_column(String(26), nullable=False)
    period_id: Mapped[str] = mapped_column(String(26), nullable=False)
    requirement_id: Mapped[str] = mapped_column(String(26), nullable=False)
    framework_key: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="not_assessed")
    evidence_links: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_by: Mapped[str] = mapped_column(String(26), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ComplianceActiveFrameworkClaimModel(Base):
    """Concurrency-safe claim: one active profile per (org, framework_key)."""

    __tablename__ = "compliance_active_framework_claims"
    __table_args__ = (
        Index("ix_cafc_profile", "organization_id", "profile_id"),
    )

    organization_id: Mapped[str] = mapped_column(String(26), primary_key=True)
    framework_key: Mapped[str] = mapped_column(String(80), primary_key=True)
    profile_id: Mapped[str] = mapped_column(String(26), nullable=False)
    claimed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
