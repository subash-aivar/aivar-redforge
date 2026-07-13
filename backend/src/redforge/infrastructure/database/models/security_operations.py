"""SQLAlchemy ORM models for the Security Operations bounded context (M15).

Three small, purpose-built tables — see migration 0023's own docstring
for the reconnaissance finding and the reuse-vs-evolve trade-off they
represent. `RuntimeComponentHealthStateModel`/`RuntimeComponentHealthTransitionModel`
are not tenant-scoped: runtime components are platform-wide, not
per-organization.
"""

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKeyConstraint, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base


class ContinuousValidationPolicyLifecycleEventModel(Base):
    """Append-only log of ContinuousValidationPolicy lifecycle
    transitions (created/activated/paused/resumed/disabled) — M14's
    policy aggregate had no durable history of this at all before M15;
    only the current `lifecycle` column survived."""

    __tablename__ = "continuous_validation_policy_lifecycle_events"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="ux_cvple_id_org"),
        ForeignKeyConstraint(
            ["policy_id", "organization_id"],
            ["continuous_validation_policies.id", "continuous_validation_policies.organization_id"],
            name="fk_cvple_same_tenant_policy",
        ),
        Index("ix_cvple_org_occurred", "organization_id", "occurred_at"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    policy_id: Mapped[str] = mapped_column(String(26), nullable=False)
    event_type: Mapped[str] = mapped_column(String(40), nullable=False)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RuntimeComponentHealthStateModel(Base):
    """Last emitted HEALTHY/DEGRADED/UNHEALTHY status per runtime
    component — used only to detect and dedup a status transition, not
    as the source of truth for current health (that stays 100%
    live-computed by application/platform/dynamic_health.py, unchanged
    by M15)."""

    __tablename__ = "runtime_component_health_state"

    component_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RuntimeComponentHealthTransitionModel(Base):
    """Durable, append-only HEALTHY<->UNHEALTHY transition history —
    the actual source the operational event feed reads runtime changes
    from. One row per genuine flip, never one per poll."""

    __tablename__ = "runtime_component_health_transitions"
    __table_args__ = (
        Index("ix_rcht_component_occurred", "component_id", "occurred_at"),
        Index("ix_rcht_occurred", "occurred_at"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    component_id: Mapped[str] = mapped_column(String(100), nullable=False)
    old_status: Mapped[str] = mapped_column(String(20), nullable=False)
    new_status: Mapped[str] = mapped_column(String(20), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
