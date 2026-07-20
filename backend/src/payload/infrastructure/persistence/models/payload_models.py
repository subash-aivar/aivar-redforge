"""SQLAlchemy models for the payload schema."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import DateTime, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

_SCHEMA = "payload"


class PayloadBase(DeclarativeBase):
    pass


class PayloadModel(PayloadBase):
    __tablename__ = "payloads"
    __table_args__ = (
        Index("ix_payloads_tenant_key", "tenant_id", "payload_key", unique=True),
        Index("ix_payloads_tenant_state", "tenant_id", "approval_state"),
        {"schema": _SCHEMA},
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    payload_key: Mapped[str] = mapped_column(String(256), nullable=False)
    payload_type: Mapped[str] = mapped_column(String(64), nullable=False)
    impact_ceiling: Mapped[str] = mapped_column(String(32), nullable=False)
    approval_state: Mapped[str] = mapped_column(String(32), nullable=False)
    current_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    versions_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    engagement_classes_json: Mapped[list[Any]] = mapped_column(JSONB, nullable=False)
    signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class PluginRegistrationModel(PayloadBase):
    __tablename__ = "plugin_registrations"
    __table_args__ = (
        Index("ix_plugin_registrations_tenant_state", "tenant_id", "approval_state"),
        {"schema": _SCHEMA},
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    plugin_type: Mapped[str] = mapped_column(String(64), nullable=False)
    plugin_version: Mapped[str] = mapped_column(String(64), nullable=False)
    plugin_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    technique_ids_json: Mapped[list[Any]] = mapped_column(JSONB, nullable=False)
    trust_level: Mapped[str] = mapped_column(String(32), nullable=False)
    approval_state: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
