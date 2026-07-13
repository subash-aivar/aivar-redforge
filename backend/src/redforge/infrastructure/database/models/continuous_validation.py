"""SQLAlchemy ORM models for the Continuous Validation bounded context (M14)."""

from datetime import datetime
from typing import Any

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


class ContinuousValidationPolicyModel(Base):
    __tablename__ = "continuous_validation_policies"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="ux_cvp_id_org"),
        Index("ix_cvp_org_lifecycle", "organization_id", "lifecycle"),
        Index("ix_cvp_org_target", "organization_id", "target_id"),
        # Scheduler poll path — global (cross-tenant) by design, mirroring
        # how DLQReplayWorker's own poll query is not tenant-scoped
        # either; tenant isolation is enforced by every OTHER read/write
        # path (REST API, claim result mapping), not by the poll query.
        Index("ix_cvp_lifecycle_next_due", "lifecycle", "next_due_at"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    target_id: Mapped[str] = mapped_column(String(26), nullable=False)
    requester_user_id: Mapped[str] = mapped_column(String(26), nullable=False)
    profile: Mapped[str] = mapped_column(String(50), nullable=False)
    cadence: Mapped[str] = mapped_column(String(20), nullable=False)
    lifecycle: Mapped[str] = mapped_column(String(20), nullable=False)
    next_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_scheduled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    claim_owner: Mapped[str | None] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ValidationStateSnapshotModel(Base):
    __tablename__ = "validation_state_snapshots"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="ux_vss_id_org"),
        UniqueConstraint("execution_id", name="ux_vss_execution"),
        ForeignKeyConstraint(
            ["continuous_policy_id", "organization_id"],
            ["continuous_validation_policies.id", "continuous_validation_policies.organization_id"],
            name="fk_vss_same_tenant_policy",
        ),
        Index("ix_vss_org_policy_captured", "organization_id", "continuous_policy_id",
              "captured_at"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    continuous_policy_id: Mapped[str] = mapped_column(String(26), nullable=False)
    execution_id: Mapped[str] = mapped_column(String(26), nullable=False)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False)
    resolved_ips: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    reachable_ports: Mapped[list[int]] = mapped_column(JSON, nullable=False, default=list)
    services: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    active_condition_keys: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    active_correlation_keys: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    content_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class SecurityDriftEventModel(Base):
    """Immutable, append-only live change feed. No update/delete
    anywhere in this bounded context — mirrors
    ValidationExecutionEventModel's own convention exactly."""

    __tablename__ = "security_drift_events"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="ux_sde_id_org"),
        UniqueConstraint(
            "execution_id", "category", "identity_key", name="ux_sde_execution_category_identity",
        ),
        ForeignKeyConstraint(
            ["continuous_policy_id", "organization_id"],
            ["continuous_validation_policies.id", "continuous_validation_policies.organization_id"],
            name="fk_sde_same_tenant_policy",
        ),
        ForeignKeyConstraint(
            ["execution_id", "organization_id"],
            ["validation_executions.id", "validation_executions.organization_id"],
            name="fk_sde_same_tenant_execution",
        ),
        Index("ix_sde_org_policy_detected", "organization_id", "continuous_policy_id",
              "detected_at"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    continuous_policy_id: Mapped[str] = mapped_column(String(26), nullable=False)
    execution_id: Mapped[str] = mapped_column(String(26), nullable=False)
    category: Mapped[str] = mapped_column(String(40), nullable=False)
    identity_key: Mapped[str] = mapped_column(String(200), nullable=False)
    summary: Mapped[str] = mapped_column(String(500), nullable=False)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
