"""SQLAlchemy ORM models for the Gated Safe Active Validation foundation — M11."""

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base


class ValidationExecutionModel(Base):
    __tablename__ = "validation_executions"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="ux_validation_executions_id_org"),
        Index("ix_validation_executions_org_status", "organization_id", "status"),
        Index("ix_validation_executions_org_target", "organization_id", "target_id"),
        Index("ix_validation_executions_org_created", "organization_id", "created_at"),
        # M14 — database-enforced scheduled-run identity: one due boundary
        # for a continuous policy can create at most one canonical
        # ValidationExecution. Partial so MANUAL/ON_DEMAND rows (which
        # never set continuous_policy_id) are never constrained by it.
        Index(
            "ux_validation_executions_policy_due",
            "continuous_policy_id",
            "scheduled_due_at",
            unique=True,
            postgresql_where=text("continuous_policy_id IS NOT NULL"),
        ),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    target_id: Mapped[str] = mapped_column(String(26), nullable=False)
    requester_user_id: Mapped[str] = mapped_column(String(26), nullable=False)
    profile: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    policy_decision_id: Mapped[str | None] = mapped_column(String(26), nullable=True)
    policy_reason_code: Mapped[str | None] = mapped_column(String(40), nullable=True)
    cancellation_requested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    limits: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    failure_reason: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # M14 — closed, server-assigned provenance. Never client-writable;
    # see ValidationExecution.__init__'s own docstring note.
    trigger: Mapped[str] = mapped_column(String(20), nullable=False, default="manual")
    continuous_policy_id: Mapped[str | None] = mapped_column(String(26), nullable=True)
    scheduled_due_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class ValidationExecutionStepModel(Base):
    __tablename__ = "validation_execution_steps"
    __table_args__ = (
        ForeignKeyConstraint(
            ["execution_id", "organization_id"],
            ["validation_executions.id", "validation_executions.organization_id"],
            name="fk_validation_step_same_tenant",
        ),
        UniqueConstraint("execution_id", "order_index", name="ux_validation_step_order"),
        Index("ix_validation_steps_org", "organization_id"),
        Index("ix_validation_steps_execution_id", "execution_id"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    execution_id: Mapped[str] = mapped_column(String(26), nullable=False)
    step_type: Mapped[str] = mapped_column(String(30), nullable=False)
    order_index: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    evidence: Mapped[list[dict[str, str]]] = mapped_column(JSON, nullable=False, default=list)
    error_category: Mapped[str | None] = mapped_column(String(40), nullable=True)
    # M12 — adaptive-plan provenance. NULL/"initial" for every M11
    # step and every NETWORK_DISCOVERY_BASELINE_V1 step the initial
    # plan itself builds; populated only for steps the deterministic
    # adaptive rule registry appended mid-execution.
    source: Mapped[str] = mapped_column(String(20), nullable=False, default="initial")
    adaptive_rule_id: Mapped[str | None] = mapped_column(String(60), nullable=True)
    adaptive_rule_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source_fact_ref: Mapped[str | None] = mapped_column(String(120), nullable=True)
    # M13 — which ProtocolValidator (if any) produced this step's
    # outcome, and the resulting ProtocolValidationState. NULL for every
    # non-protocol step (DNS/TCP/TLS/HTTP/port discovery all predate
    # M13's validator registry and keep their own status/evidence shape).
    validator_id: Mapped[str | None] = mapped_column(String(60), nullable=True)
    validator_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol_validation_state: Mapped[str | None] = mapped_column(String(20), nullable=True)


class ValidationExecutionEventModel(Base):
    """Immutable, append-only live-progress log. No update/delete
    anywhere in this bounded context — see domain.validation_execution.
    execution_event's module docstring."""

    __tablename__ = "validation_execution_events"
    __table_args__ = (
        ForeignKeyConstraint(
            ["execution_id", "organization_id"],
            ["validation_executions.id", "validation_executions.organization_id"],
            name="fk_validation_event_same_tenant",
        ),
        UniqueConstraint("execution_id", "sequence", name="ux_validation_event_sequence"),
        Index(
            "ix_validation_events_org_execution_seq",
            "organization_id", "execution_id", "sequence",
        ),
        Index("ix_validation_events_org_occurred", "organization_id", "occurred_at"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    execution_id: Mapped[str] = mapped_column(String(26), nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(String(40), nullable=False)
    payload: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False, default=dict)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
