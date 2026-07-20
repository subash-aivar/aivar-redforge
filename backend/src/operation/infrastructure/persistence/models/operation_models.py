"""SQLAlchemy models for the operation schema."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base

_SCHEMA = "operation"


class OperationModel(Base):
    __tablename__ = "operations"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    engagement_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    classification: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(48), nullable=False)
    risk: Mapped[str] = mapped_column(String(32), nullable=False)
    abort_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (
        Index("ix_operations_tenant_id", "tenant_id"),
        Index("ix_operations_tenant_engagement", "tenant_id", "engagement_id"),
        Index("ix_operations_tenant_state", "tenant_id", "state"),
        {"schema": _SCHEMA},
    )


class ExecutionStepModel(Base):
    __tablename__ = "execution_steps"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    operation_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{_SCHEMA}.operations.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    step_type: Mapped[str] = mapped_column(String(48), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    impact_ceiling: Mapped[str | None] = mapped_column(String(32), nullable=True)
    modifies_persistent_state: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    constraints_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    technique_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    target_asset_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    mitre_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    rate_limit_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    window_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    output_ref: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        Index("ix_execution_steps_tenant_operation", "tenant_id", "operation_id"),
        {"schema": _SCHEMA},
    )


class StepDependencyModel(Base):
    __tablename__ = "step_dependencies"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    operation_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{_SCHEMA}.operations.id", ondelete="CASCADE"),
        nullable=False,
    )
    from_step_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    to_step_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)

    __table_args__ = (
        Index("ix_step_dependencies_tenant_operation", "tenant_id", "operation_id"),
        UniqueConstraint(
            "operation_id",
            "from_step_id",
            "to_step_id",
            name="uq_step_dependencies_edge",
        ),
        {"schema": _SCHEMA},
    )


class OperationApprovalModel(Base):
    __tablename__ = "operation_approvals"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    operation_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{_SCHEMA}.operations.id", ondelete="CASCADE"),
        nullable=False,
    )
    operator_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    authority: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False)
    approved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        Index("ix_operation_approvals_tenant_operation", "tenant_id", "operation_id"),
        {"schema": _SCHEMA},
    )


class OperationObjectiveModel(Base):
    __tablename__ = "operation_objectives"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    operation_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{_SCHEMA}.operations.id", ondelete="CASCADE"),
        nullable=False,
    )
    description: Mapped[str] = mapped_column(Text, nullable=False)
    success_criteria: Mapped[str] = mapped_column(Text, nullable=False)
    is_primary: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    __table_args__ = (
        Index("ix_operation_objectives_tenant_operation", "tenant_id", "operation_id"),
        {"schema": _SCHEMA},
    )


class ExecutionPlanVersionModel(Base):
    __tablename__ = "execution_plan_versions"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    operation_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    snapshot: Mapped[str] = mapped_column(Text, nullable=False)
    plan_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    signed_by_operator_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    signed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (
        Index("ix_plan_versions_tenant_operation", "tenant_id", "operation_id"),
        Index("ix_plan_versions_tenant_state", "tenant_id", "state"),
        UniqueConstraint(
            "tenant_id",
            "operation_id",
            "version_number",
            name="uq_plan_versions_op_number",
        ),
        {"schema": _SCHEMA},
    )
