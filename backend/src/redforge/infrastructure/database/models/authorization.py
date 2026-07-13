"""SQLAlchemy ORM models for the Security Authorization foundation — M10."""

from datetime import datetime

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base


class SecurityAuthorizationModel(Base):
    __tablename__ = "security_authorizations"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="ux_security_authorizations_id_org"),
        Index("ix_security_authorizations_org_status", "organization_id", "status"),
        Index("ix_security_authorizations_org_valid_until", "organization_id", "valid_until"),
        Index("ix_security_authorizations_org_requester", "organization_id", "requester_user_id"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    requester_user_id: Mapped[str] = mapped_column(String(26), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    action_classes: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class SecurityAuthorizationScopeModel(Base):
    __tablename__ = "security_authorization_scope"
    __table_args__ = (
        ForeignKeyConstraint(
            ["authorization_id", "organization_id"],
            ["security_authorizations.id", "security_authorizations.organization_id"],
            name="fk_authorization_scope_same_tenant",
        ),
        Index("ix_authorization_scope_org", "organization_id"),
        Index("ix_authorization_scope_authorization_id", "authorization_id"),
        Index(
            "ix_authorization_scope_org_entity", "organization_id", "entity_type", "entity_id",
        ),
        UniqueConstraint(
            "authorization_id", "entity_type", "entity_id",
            name="ux_authorization_scope_entry",
        ),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    authorization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(20), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(64), nullable=False)


class SecurityAuthorizationApprovalModel(Base):
    __tablename__ = "security_authorization_approvals"
    __table_args__ = (
        ForeignKeyConstraint(
            ["authorization_id", "organization_id"],
            ["security_authorizations.id", "security_authorizations.organization_id"],
            name="fk_authorization_approval_same_tenant",
        ),
        Index("ix_authorization_approvals_org", "organization_id"),
        Index("ix_authorization_approvals_authorization_id", "authorization_id"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    authorization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    requester_user_id: Mapped[str] = mapped_column(String(26), nullable=False)
    approver_user_id: Mapped[str | None] = mapped_column(String(26), nullable=True)
    decision: Mapped[str | None] = mapped_column(String(20), nullable=True)
    reason: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SecurityAuthorizationDecisionModel(Base):
    """Immutable audit log of every ExecutionPolicyService.evaluate() call.

    authorization_id is nullable — a DENY of AUTHORIZATION_NOT_FOUND or
    ACTION_CLASS_DENIED has no authorization to reference at all. No
    foreign key to security_authorizations for that reason (a decision
    row must never be blocked from being written by a missing
    authorization — that would defeat "every decision is auditable").
    """

    __tablename__ = "security_authorization_decisions"
    __table_args__ = (
        Index("ix_authorization_decisions_org_time", "organization_id", "evaluated_at"),
        Index(
            "ix_authorization_decisions_org_authorization",
            "organization_id", "authorization_id",
        ),
        Index("ix_authorization_decisions_org_decision", "organization_id", "decision"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    actor_user_id: Mapped[str] = mapped_column(String(26), nullable=False)
    authorization_id: Mapped[str | None] = mapped_column(String(26), nullable=True)
    action_class: Mapped[str | None] = mapped_column(String(30), nullable=True)
    raw_action_class: Mapped[str] = mapped_column(String(100), nullable=False)
    entity_refs: Mapped[list[dict[str, str]]] = mapped_column(JSON, nullable=False)
    decision: Mapped[str] = mapped_column(String(20), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(40), nullable=False)
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
