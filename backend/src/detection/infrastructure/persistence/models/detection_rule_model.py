"""SQLAlchemy models for DetectionRule aggregate."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from redforge.infrastructure.database.base import Base

_SCHEMA = "detection"


class DetectionRuleModel(Base):
    __tablename__ = "detection_rules"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    rule_key: Mapped[str] = mapped_column(String(256), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    lifecycle_state: Mapped[str] = mapped_column(String(32), nullable=False)
    author_identity: Mapped[str] = mapped_column(String(256), nullable=False)
    reviewer_identity: Mapped[str | None] = mapped_column(String(256), nullable=True)
    current_logic_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    telemetry_sources_json: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    asset_scope_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    throttle_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    fp_profile_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    tags_json: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    external_refs_json: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    versions: Mapped[list[RuleVersionModel]] = relationship(
        "RuleVersionModel",
        back_populates="rule",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    test_cases: Mapped[list[RuleTestCaseModel]] = relationship(
        "RuleTestCaseModel",
        back_populates="rule",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    test_results: Mapped[list[RuleTestResultModel]] = relationship(
        "RuleTestResultModel",
        back_populates="rule",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    mitre_mappings: Mapped[list[MitreAttackMappingModel]] = relationship(
        "MitreAttackMappingModel",
        back_populates="rule",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    __table_args__ = (
        UniqueConstraint("tenant_id", "rule_key", name="uq_detection_rules_tenant_key"),
        Index("ix_detection_rules_tenant_id", "tenant_id"),
        Index("ix_detection_rules_tenant_lifecycle", "tenant_id", "lifecycle_state"),
        Index("ix_detection_rules_tenant_category", "tenant_id", "category"),
        {"schema": _SCHEMA},
    )


class RuleVersionModel(Base):
    __tablename__ = "rule_versions"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    rule_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{_SCHEMA}.detection_rules.id", ondelete="CASCADE"),
        nullable=False,
    )
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    semver: Mapped[str] = mapped_column(String(32), nullable=False)
    logic_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    change_summary: Mapped[str] = mapped_column(Text, nullable=False)
    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    published_by: Mapped[str] = mapped_column(String(256), nullable=False)

    rule: Mapped[DetectionRuleModel] = relationship("DetectionRuleModel", back_populates="versions")

    __table_args__ = (
        UniqueConstraint("rule_id", "semver", name="uq_rule_versions_rule_semver"),
        Index("ix_rule_versions_tenant_id", "tenant_id"),
        Index("ix_rule_versions_rule_id", "rule_id"),
        {"schema": _SCHEMA},
    )


class RuleTestCaseModel(Base):
    __tablename__ = "rule_test_cases"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    rule_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{_SCHEMA}.detection_rules.id", ondelete="CASCADE"),
        nullable=False,
    )
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    input_payload_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    expected_match: Mapped[bool] = mapped_column(Boolean, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    rule: Mapped[DetectionRuleModel] = relationship(
        "DetectionRuleModel", back_populates="test_cases"
    )

    __table_args__ = (
        UniqueConstraint("rule_id", "name", name="uq_rule_test_cases_rule_name"),
        Index("ix_rule_test_cases_rule_id", "rule_id"),
        Index("ix_rule_test_cases_tenant_id", "tenant_id"),
        {"schema": _SCHEMA},
    )


class RuleTestResultModel(Base):
    __tablename__ = "rule_test_results"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    rule_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{_SCHEMA}.detection_rules.id", ondelete="CASCADE"),
        nullable=False,
    )
    test_case_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    rule_version: Mapped[str | None] = mapped_column(String(32), nullable=True)

    rule: Mapped[DetectionRuleModel] = relationship(
        "DetectionRuleModel", back_populates="test_results"
    )

    __table_args__ = (
        Index("ix_rule_test_results_rule_id", "rule_id"),
        Index("ix_rule_test_results_tenant_id", "tenant_id"),
        Index("ix_rule_test_results_test_case_id", "test_case_id"),
        {"schema": _SCHEMA},
    )


class MitreAttackMappingModel(Base):
    __tablename__ = "rule_mitre_mappings"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    rule_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{_SCHEMA}.detection_rules.id", ondelete="CASCADE"),
        nullable=False,
    )
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    tactic: Mapped[str] = mapped_column(String(128), nullable=False)
    technique: Mapped[str] = mapped_column(String(32), nullable=False)
    sub_technique: Mapped[str | None] = mapped_column(String(32), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    # unused float column reserved for future coverage weight
    weight: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)

    rule: Mapped[DetectionRuleModel] = relationship(
        "DetectionRuleModel", back_populates="mitre_mappings"
    )

    __table_args__ = (
        Index("ix_rule_mitre_rule_id", "rule_id"),
        Index("ix_rule_mitre_tenant_technique", "tenant_id", "technique"),
        {"schema": _SCHEMA},
    )
