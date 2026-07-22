"""ORM models mapping the `integration_hub` schema (migrations 0125-0126)."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base

_SCHEMA = "integration_hub"


class ConnectorRegistrationModel(Base):
    __tablename__ = "connector_registrations"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    connector_type: Mapped[str] = mapped_column(String(50), nullable=False)
    display_name: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    credential_vault_key: Mapped[str] = mapped_column(Text, nullable=False)
    credential_type: Mapped[str] = mapped_column(String(30), nullable=False)
    base_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    configuration: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    circuit_state: Mapped[str] = mapped_column(String(20), nullable=False)
    circuit_failure_count: Mapped[int] = mapped_column(Integer, nullable=False)
    circuit_opened_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_health_check_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class ConnectorHealthRecordModel(Base):
    __tablename__ = "connector_health_records"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    connector_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    response_time_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
