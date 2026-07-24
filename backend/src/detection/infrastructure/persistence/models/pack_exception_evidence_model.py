"""SQLAlchemy models for DetectionPack, DetectionException, DetectionEvidence."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base

_JSONB_PORTABLE = JSON().with_variant(JSONB, "postgresql")


_SCHEMA = "detection"


class DetectionPackModel(Base):
    __tablename__ = "detection_packs"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    pack_key: Mapped[str] = mapped_column(String(128), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    lifecycle_state: Mapped[str] = mapped_column(String(32), nullable=False)
    semver: Mapped[str] = mapped_column(String(32), nullable=False)
    maintainer_json: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    subscription_json: Mapped[dict[str, Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=dict
    )
    compliance_framework_json: Mapped[dict[str, Any] | None] = mapped_column(
        _JSONB_PORTABLE, nullable=True
    )
    coverage_json: Mapped[dict[str, Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=dict
    )
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=dict
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (
        Index("ix_detection_packs_tenant_id", "tenant_id"),
        Index("ix_detection_packs_tenant_key", "tenant_id", "pack_key", unique=True),
        Index("ix_detection_packs_tenant_state", "tenant_id", "lifecycle_state"),
        {"schema": _SCHEMA},
    )


class DetectionPackRuleModel(Base):
    __tablename__ = "detection_pack_rules"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    pack_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{_SCHEMA}.detection_packs.id", ondelete="CASCADE"),
        nullable=False,
    )
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    optional: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        Index("ix_detection_pack_rules_pack", "pack_id"),
        Index("ix_detection_pack_rules_tenant_rule", "tenant_id", "rule_id"),
        {"schema": _SCHEMA},
    )


class DetectionPackVersionModel(Base):
    __tablename__ = "detection_pack_versions"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    pack_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{_SCHEMA}.detection_packs.id", ondelete="CASCADE"),
        nullable=False,
    )
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    rule_snapshots_json: Mapped[list[Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=list
    )
    release_notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    released_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        Index("ix_detection_pack_versions_pack", "pack_id"),
        Index("ix_detection_pack_versions_tenant", "tenant_id"),
        {"schema": _SCHEMA},
    )


class DetectionExceptionModel(Base):
    __tablename__ = "detection_exceptions"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    exception_type: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    scope_json: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    justification_json: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    requester: Mapped[str] = mapped_column(String(256), nullable=False)
    approver: Mapped[str | None] = mapped_column(String(256), nullable=True)
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    affected_rules_json: Mapped[list[Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=list
    )
    asset_scope_json: Mapped[dict[str, Any] | None] = mapped_column(_JSONB_PORTABLE, nullable=True)
    compliance_impact_acknowledged: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (
        Index("ix_detection_exceptions_tenant_id", "tenant_id"),
        Index("ix_detection_exceptions_tenant_state", "tenant_id", "state"),
        Index("ix_detection_exceptions_tenant_valid_until", "tenant_id", "valid_until"),
        {"schema": _SCHEMA},
    )


class DetectionEvidenceModel(Base):
    __tablename__ = "detection_evidence"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    storage_ref: Mapped[str] = mapped_column(String(2048), nullable=False)
    collected_by: Mapped[str] = mapped_column(String(256), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    integrity_status: Mapped[str] = mapped_column(String(32), nullable=False)
    finding_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    exception_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    simulation_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (
        Index("ix_detection_evidence_tenant_id", "tenant_id"),
        Index("ix_detection_evidence_tenant_finding", "tenant_id", "finding_id"),
        Index("ix_detection_evidence_tenant_exception", "tenant_id", "exception_id"),
        Index("ix_detection_evidence_tenant_hash", "tenant_id", "payload_hash"),
        {"schema": _SCHEMA},
    )
