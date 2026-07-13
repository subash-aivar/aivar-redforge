"""SQLAlchemy ORM models for the Network Security bounded context — M16.

See migration 0024's own docstring for the reuse-vs-new rationale.
"""

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


class NetworkMonitoringPolicyModel(Base):
    __tablename__ = "network_monitoring_policies"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="ux_nmp_id_org"),
        Index("ix_nmp_org_lifecycle", "organization_id", "lifecycle"),
        Index("ix_nmp_org_target", "organization_id", "target_asset_id"),
        Index("ix_nmp_lifecycle_next_due", "lifecycle", "next_due_at"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    target_asset_id: Mapped[str] = mapped_column(String(26), nullable=False)
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


class NetworkValidationRunModel(Base):
    __tablename__ = "network_validation_runs"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="ux_nvr_id_org"),
        Index("ix_nvr_org_status", "organization_id", "status"),
        Index("ix_nvr_org_target", "organization_id", "target_asset_id"),
        Index("ix_nvr_org_created", "organization_id", "created_at"),
        Index(
            "ux_nvr_policy_due", "continuous_policy_id", "scheduled_due_at",
            unique=True, postgresql_where=text("continuous_policy_id IS NOT NULL"),
        ),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    target_asset_id: Mapped[str] = mapped_column(String(26), nullable=False)
    requester_user_id: Mapped[str] = mapped_column(String(26), nullable=False)
    profile: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    trigger: Mapped[str] = mapped_column(String(20), nullable=False, default="manual")
    continuous_policy_id: Mapped[str | None] = mapped_column(String(26), nullable=True)
    scheduled_due_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    authorization_id: Mapped[str | None] = mapped_column(String(26), nullable=True)
    failure_reason: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    cancellation_requested: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class NetworkStateSnapshotModel(Base):
    __tablename__ = "network_state_snapshots"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="ux_nss_id_org"),
        UniqueConstraint("run_id", name="ux_nss_run"),
        ForeignKeyConstraint(
            ["policy_id", "organization_id"],
            ["network_monitoring_policies.id", "network_monitoring_policies.organization_id"],
            name="fk_nss_same_tenant_policy",
        ),
        Index("ix_nss_org_policy_captured", "organization_id", "policy_id", "captured_at"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    policy_id: Mapped[str] = mapped_column(String(26), nullable=False)
    run_id: Mapped[str] = mapped_column(String(26), nullable=False)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False)
    resolved_ips: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    reachable_ports: Mapped[list[int]] = mapped_column(JSON, nullable=False)
    services: Mapped[list[Any]] = mapped_column(JSON, nullable=False)
    active_condition_keys: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    active_correlation_keys: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    content_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class NetworkDriftEventModel(Base):
    __tablename__ = "network_drift_events"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="ux_nde_id_org"),
        UniqueConstraint("run_id", "category", "identity_key", name="ux_nde_run_category_identity"),
        ForeignKeyConstraint(
            ["policy_id", "organization_id"],
            ["network_monitoring_policies.id", "network_monitoring_policies.organization_id"],
            name="fk_nde_same_tenant_policy",
        ),
        Index("ix_nde_org_policy_detected", "organization_id", "policy_id", "detected_at"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    policy_id: Mapped[str] = mapped_column(String(26), nullable=False)
    run_id: Mapped[str] = mapped_column(String(26), nullable=False)
    category: Mapped[str] = mapped_column(String(40), nullable=False)
    identity_key: Mapped[str] = mapped_column(String(200), nullable=False)
    summary: Mapped[str] = mapped_column(String(500), nullable=False)
    detail: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class NetworkObservationModel(Base):
    """Durable, bounded, allowlisted observation record — see
    application/network_security/orchestrator.py's docstring for the
    exact allowlisted `data` fields per observation_type. Never raw
    packets/banners/credentials/secrets."""

    __tablename__ = "network_observations"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="ux_no_id_org"),
        Index("ix_no_org_asset_observed", "organization_id", "asset_id", "observed_at"),
        Index("ix_no_org_run", "organization_id", "run_id"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    run_id: Mapped[str] = mapped_column(String(26), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(26), nullable=False)
    observation_type: Mapped[str] = mapped_column(String(40), nullable=False)
    method: Mapped[str] = mapped_column(String(40), nullable=False)
    outcome: Mapped[str] = mapped_column(String(40), nullable=False)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False)
    data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class NetworkMonitoringPolicyLifecycleEventModel(Base):
    __tablename__ = "network_monitoring_policy_lifecycle_events"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="ux_nmple_id_org"),
        Index("ix_nmple_org_occurred", "organization_id", "occurred_at"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    policy_id: Mapped[str] = mapped_column(String(26), nullable=False)
    event_type: Mapped[str] = mapped_column(String(40), nullable=False)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class NetworkValidationRunEventModel(Base):
    __tablename__ = "network_validation_run_events"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="ux_nvre_id_org"),
        Index("ix_nvre_org_occurred", "organization_id", "occurred_at"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    run_id: Mapped[str] = mapped_column(String(26), nullable=False)
    event_type: Mapped[str] = mapped_column(String(40), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
