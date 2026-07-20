"""ORM models for the engagement schema."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    Boolean,
    DateTime,
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

_SCHEMA = "engagement"


class EngagementModel(Base):
    __tablename__ = "engagements"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    classification: Mapped[str] = mapped_column(String(64), nullable=False)
    owner_id: Mapped[str] = mapped_column(String(256), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    kill_switch_state: Mapped[str] = mapped_column(String(32), nullable=False)
    engagement_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    scope_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    approval_policy_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    window_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    objectives_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    pending_scope_expansion_json: Mapped[list[Any] | None] = mapped_column(
        JSONB, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    phases: Mapped[list[EngagementPhaseModel]] = relationship(
        "EngagementPhaseModel",
        back_populates="engagement",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    approvals: Mapped[list[EngagementApprovalModel]] = relationship(
        "EngagementApprovalModel",
        back_populates="engagement",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    participants: Mapped[list[EngagementParticipantModel]] = relationship(
        "EngagementParticipantModel",
        back_populates="engagement",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    rules_of_engagement: Mapped[list[RulesOfEngagementModel]] = relationship(
        "RulesOfEngagementModel",
        back_populates="engagement",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    target_scope_entries: Mapped[list[TargetScopeEntryModel]] = relationship(
        "TargetScopeEntryModel",
        back_populates="engagement",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    __table_args__ = (
        Index("ix_engagements_tenant_id", "tenant_id"),
        Index("ix_engagements_tenant_state", "tenant_id", "state"),
        {"schema": _SCHEMA},
    )


class EngagementPhaseModel(Base):
    __tablename__ = "engagement_phases"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    engagement_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{_SCHEMA}.engagements.id", ondelete="CASCADE"),
        nullable=False,
    )
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    engagement: Mapped[EngagementModel] = relationship(
        "EngagementModel", back_populates="phases"
    )

    __table_args__ = (
        Index("ix_engagement_phases_engagement_id", "engagement_id"),
        Index("ix_engagement_phases_tenant_id", "tenant_id"),
        {"schema": _SCHEMA},
    )


class EngagementApprovalModel(Base):
    __tablename__ = "engagement_approvals"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    engagement_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{_SCHEMA}.engagements.id", ondelete="CASCADE"),
        nullable=False,
    )
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    approver_id: Mapped[str] = mapped_column(String(256), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False)
    approval_scope: Mapped[str] = mapped_column(String(128), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_by: Mapped[str | None] = mapped_column(String(256), nullable=True)

    engagement: Mapped[EngagementModel] = relationship(
        "EngagementModel", back_populates="approvals"
    )

    __table_args__ = (
        Index("ix_engagement_approvals_engagement_id", "engagement_id"),
        Index("ix_engagement_approvals_tenant_id", "tenant_id"),
        {"schema": _SCHEMA},
    )


class EngagementParticipantModel(Base):
    __tablename__ = "engagement_participants"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    engagement_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{_SCHEMA}.engagements.id", ondelete="CASCADE"),
        nullable=False,
    )
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    operator_id: Mapped[str] = mapped_column(String(256), nullable=False)
    role: Mapped[str] = mapped_column(String(128), nullable=False)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    removed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    engagement: Mapped[EngagementModel] = relationship(
        "EngagementModel", back_populates="participants"
    )

    __table_args__ = (
        Index("ix_engagement_participants_engagement_id", "engagement_id"),
        Index("ix_engagement_participants_tenant_id", "tenant_id"),
        UniqueConstraint(
            "engagement_id",
            "operator_id",
            "added_at",
            name="uq_engagement_participants_op_added",
        ),
        {"schema": _SCHEMA},
    )


class RulesOfEngagementModel(Base):
    __tablename__ = "rules_of_engagement"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    engagement_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{_SCHEMA}.engagements.id", ondelete="CASCADE"),
        nullable=False,
    )
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    constraints_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    signed_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    signed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    engagement: Mapped[EngagementModel] = relationship(
        "EngagementModel", back_populates="rules_of_engagement"
    )

    __table_args__ = (
        Index("ix_rules_of_engagement_engagement_id", "engagement_id"),
        UniqueConstraint(
            "engagement_id",
            "version",
            name="uq_rules_of_engagement_version",
        ),
        {"schema": _SCHEMA},
    )


class TargetScopeEntryModel(Base):
    __tablename__ = "target_scope_entries"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    engagement_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{_SCHEMA}.engagements.id", ondelete="CASCADE"),
        nullable=False,
    )
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    asset_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(512), nullable=True)

    engagement: Mapped[EngagementModel] = relationship(
        "EngagementModel", back_populates="target_scope_entries"
    )

    __table_args__ = (
        Index("ix_target_scope_entries_engagement_id", "engagement_id"),
        Index("ix_target_scope_entries_tenant_asset", "tenant_id", "asset_id"),
        UniqueConstraint(
            "engagement_id",
            "asset_id",
            name="uq_target_scope_engagement_asset",
        ),
        {"schema": _SCHEMA},
    )


class TargetAuthorizationModel(Base):
    __tablename__ = "target_authorizations"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    engagement_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    asset_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    techniques_json: Mapped[list[Any]] = mapped_column(JSONB, nullable=False)
    constraints_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    granted_by: Mapped[str] = mapped_column(String(256), nullable=False)
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    phase_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    destruct_approval_granted: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __table_args__ = (
        Index("ix_target_authorizations_tenant_id", "tenant_id"),
        Index("ix_target_authorizations_engagement", "tenant_id", "engagement_id"),
        Index("ix_target_authorizations_asset", "tenant_id", "asset_id"),
        {"schema": _SCHEMA},
    )
