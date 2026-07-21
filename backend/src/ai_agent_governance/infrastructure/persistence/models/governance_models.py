from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Boolean, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class AgentGovernanceBase(DeclarativeBase):
    pass


class AgentOperationalEnvelopeModel(AgentGovernanceBase):
    __tablename__ = "agent_operational_envelopes"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "ai_system_asset_id",
            "envelope_version",
            name="uq_envelope_tenant_asset_version",
        ),
        {"schema": "ai_agent_governance"},
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False, index=True)
    ai_system_asset_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    state: Mapped[str] = mapped_column(String(64), nullable=False)
    envelope_version: Mapped[int] = mapped_column(Integer, nullable=False)
    is_current: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    actions_json: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    resource_scopes_json: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    max_data_sensitivity: Mapped[str] = mapped_column(String(64), nullable=False)
    rate_ceilings_json: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    requires_human_approval_json: Mapped[list[Any]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    approved_by_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    effective_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    effective_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class AgentDeviationEventModel(AgentGovernanceBase):
    __tablename__ = "agent_deviation_events"
    __table_args__ = ({"schema": "ai_agent_governance"},)

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False, index=True)
    envelope_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    envelope_version: Mapped[int] = mapped_column(Integer, nullable=False)
    ai_system_asset_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    deviation_type: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(64), nullable=False)
    observed_action_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    review_state: Mapped[str] = mapped_column(String(64), nullable=False)
    review_notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    linked_revision_event_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    idempotency_key: Mapped[str] = mapped_column(String(256), nullable=False)


class AgentActionIdempotencyModel(AgentGovernanceBase):
    __tablename__ = "agent_action_idempotency"
    __table_args__ = (
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_agent_action_idempotency"),
        {"schema": "ai_agent_governance"},
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(256), nullable=False)
    result: Mapped[str] = mapped_column(String(64), nullable=False)
