"""ORM models for the campaign schema."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from redforge.infrastructure.database.base import Base

_JSONB_PORTABLE = JSON().with_variant(JSONB, "postgresql")


_SCHEMA = "campaign"


class CampaignModel(Base):
    __tablename__ = "campaigns"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    classification: Mapped[str] = mapped_column(String(64), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    owner_id: Mapped[str] = mapped_column(String(256), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    engagement_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    engagement_tenant_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    safety_policy_json: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    approval_policy_json: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    schedule_json: Mapped[dict[str, Any] | None] = mapped_column(_JSONB_PORTABLE, nullable=True)
    target_selection_rules_json: Mapped[list[Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=list
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    approvals: Mapped[list[CampaignApprovalModel]] = relationship(
        "CampaignApprovalModel",
        back_populates="campaign",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    objectives: Mapped[list[CampaignObjectiveModel]] = relationship(
        "CampaignObjectiveModel",
        back_populates="campaign",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    __table_args__ = (
        Index("ix_campaigns_tenant_id", "tenant_id"),
        Index("ix_campaigns_tenant_state", "tenant_id", "state"),
        Index("ix_campaigns_tenant_engagement", "tenant_id", "engagement_id"),
        {"schema": _SCHEMA},
    )


class CampaignApprovalModel(Base):
    __tablename__ = "campaign_approvals"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    campaign_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{_SCHEMA}.campaigns.id", ondelete="CASCADE"),
        nullable=False,
    )
    approver_id: Mapped[str] = mapped_column(String(256), nullable=False)
    signature: Mapped[str] = mapped_column(String(1024), nullable=False)
    approval_scope: Mapped[str] = mapped_column(String(128), nullable=False)
    approved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[str | None] = mapped_column(String(256), nullable=True)

    campaign: Mapped[CampaignModel] = relationship("CampaignModel", back_populates="approvals")

    __table_args__ = (
        Index("ix_campaign_approvals_campaign_id", "campaign_id"),
        {"schema": _SCHEMA},
    )


class CampaignObjectiveModel(Base):
    __tablename__ = "campaign_objectives"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    campaign_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{_SCHEMA}.campaigns.id", ondelete="CASCADE"),
        nullable=False,
    )
    objective_type: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(String(1024), nullable=False)
    evaluation_criteria_json: Mapped[dict[str, Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False,
    )
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    sealed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    campaign: Mapped[CampaignModel] = relationship("CampaignModel", back_populates="objectives")

    __table_args__ = (
        Index("ix_campaign_objectives_campaign_id", "campaign_id"),
        {"schema": _SCHEMA},
    )


class CampaignInstanceModel(Base):
    __tablename__ = "campaign_instances"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    campaign_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    run_number: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    resolved_targets_json: Mapped[list[Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=list,
    )
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __table_args__ = (
        Index("ix_campaign_instances_tenant_id", "tenant_id"),
        Index("ix_campaign_instances_campaign_id", "campaign_id"),
        Index("ix_campaign_instances_tenant_state", "tenant_id", "state"),
        {"schema": _SCHEMA},
    )
