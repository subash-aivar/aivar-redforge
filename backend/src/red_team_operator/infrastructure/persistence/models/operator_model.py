"""ORM model for the RedTeamOperator aggregate."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base

_SCHEMA = "operator"


class RedTeamOperatorModel(Base):
    __tablename__ = "operators"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    identity_ref: Mapped[str] = mapped_column(String(256), nullable=False)
    display_name: Mapped[str] = mapped_column(String(256), nullable=False)
    clearance_level: Mapped[str] = mapped_column(String(32), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    certifications_json: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    approval_scopes_json: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    active_engagement_ids_json: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    status_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    status_authority: Mapped[str | None] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __table_args__ = (
        Index("ix_operator_operators_tenant_id", "tenant_id"),
        Index("ix_operator_operators_tenant_state", "tenant_id", "state"),
        Index("ix_operator_operators_tenant_identity", "tenant_id", "identity_ref"),
        {"schema": _SCHEMA},
    )
