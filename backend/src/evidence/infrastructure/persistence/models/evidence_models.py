
"""SQLAlchemy models for the evidence schema."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Boolean, DateTime, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

_SCHEMA = "evidence"


class EvidenceBase(DeclarativeBase):
    pass


class ExecutionEvidenceModel(EvidenceBase):
    __tablename__ = "execution_evidence"
    __table_args__ = (
        Index("ix_execution_evidence_tenant_operation", "tenant_id", "operation_id"),
        Index("ix_execution_evidence_tenant_action", "tenant_id", "action_id"),
        {"schema": _SCHEMA},
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    storage_ref: Mapped[str] = mapped_column(String(512), nullable=False)
    key_id: Mapped[str] = mapped_column(String(256), nullable=False)
    key_version: Mapped[int] = mapped_column(Integer, nullable=False)
    action_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    engagement_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    operation_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    collected_by: Mapped[str] = mapped_column(String(256), nullable=False)
    integrity_status: Mapped[str] = mapped_column(String(32), nullable=False)
    retention_class: Mapped[str] = mapped_column(String(32), nullable=False)
    corrections_ref: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    custody_chain_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    quarantined: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    retention_expired: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class EvidenceChainModel(EvidenceBase):
    __tablename__ = "evidence_chains"
    __table_args__ = (
        Index("ix_evidence_chains_tenant_operation", "tenant_id", "operation_id", unique=True),
        {"schema": _SCHEMA},
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    operation_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    engagement_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    chain_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    integrity_status: Mapped[str] = mapped_column(String(32), nullable=False)
    entries_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    sealed_by_operator_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True), nullable=True
    )
    sealed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sealer_role: Mapped[str | None] = mapped_column(String(128), nullable=True)
    seal_signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    submission_destination_ref: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
