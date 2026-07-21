"""SQLAlchemy ORM models for campaignexecution context."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID


class ExecutionBase(DeclarativeBase):
    pass


class TaskGraphExecutionModel(ExecutionBase):
    __tablename__ = "task_graph_executions"
    __table_args__ = {"schema": "campaignexecution"}  # noqa: RUF012

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)

    campaign_instance_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), nullable=False, index=True
    )
    campaign_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    engagement_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)

    graph_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    graph_version: Mapped[str] = mapped_column(String(32), nullable=False)

    state: Mapped[str] = mapped_column(String(32), nullable=False, index=True)

    # Policy snapshot stored as JSONB
    policy_snapshot_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict
    )

    # Pending approval gate
    pending_approval_gate_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)

    # Objective states snapshot
    objective_states_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict
    )

    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    task_records: Mapped[list[TaskExecutionRecordModel]] = relationship(
        "TaskExecutionRecordModel",
        back_populates="execution",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class TaskExecutionRecordModel(ExecutionBase):
    __tablename__ = "task_execution_records"
    __table_args__ = {"schema": "campaignexecution"}  # noqa: RUF012

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    execution_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("campaignexecution.task_graph_executions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    task_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    outcome: Mapped[str | None] = mapped_column(String(32), nullable=True)
    operation_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    operation_tenant_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_rollback_task: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    execution: Mapped[TaskGraphExecutionModel] = relationship(
        "TaskGraphExecutionModel", back_populates="task_records"
    )


class CampaignSafetyMonitorModel(ExecutionBase):
    __tablename__ = "campaign_safety_monitors"
    __table_args__ = {"schema": "campaignexecution"}  # noqa: RUF012

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)

    campaign_instance_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), nullable=False, unique=True, index=True
    )
    campaign_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)

    monitor_state: Mapped[str] = mapped_column(String(32), nullable=False)
    auto_abort_triggered: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Active operation IDs stored as JSONB array
    active_operation_ids_json: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list
    )

    # Policy snapshot
    policy_snapshot_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict
    )

    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
