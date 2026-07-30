"""ORM models for the `EnterpriseRiskProfile` aggregate (M48E).

Three tables:

- ``risk_engine_profiles`` — the aggregate root row (one per
  `EnterpriseRiskProfile`), holding the current `composite_score`
  denormalized as scalar columns (mirrors `credential_vault`'s
  precedent of denormalizing a small value object onto its owning
  row rather than a satellite table for something that only ever has
  one "current" value).
- ``risk_engine_profile_contributions`` — child rows for the
  aggregate's `contributions` tuple. Rebuilt in full on every
  `save()` (delete-then-insert) because `RiskContribution` is a
  frozen, identity-less value-shaped entity that is wholesale
  replaced by `EnterpriseRiskProfile.recompute_score`, never
  individually mutated — there is nothing to diff.
- ``risk_engine_profile_score_history`` — an append-only log of every
  `CompositeRiskScore` a profile has ever had, written once per
  `recompute_score` (never on lifecycle-only transitions where
  `composite_score` doesn't change). Backs
  `EnterpriseRiskProfileRepository.score_history`, which the frozen
  M48C `RiskTimelineApplicationService` depends on and which the
  aggregate itself has no field for (it only holds *current* state).
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from redforge.infrastructure.database.base import Base


class RiskProfileModel(Base):
    __tablename__ = "risk_engine_profiles"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    subject_reference: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    accepted_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Denormalized `CompositeRiskScore` — None until the first `recompute_score`.
    composite_score_value: Mapped[float | None] = mapped_column(Float(), nullable=True)
    composite_weight_profile_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    composite_computed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # lazy="selectin": mandatory under AsyncSession — the default
    # lazy="select" strategy issues an implicit lazy-load query the
    # first time the attribute is accessed, which raises
    # `MissingGreenlet` outside of an awaited context. `selectin` eager
    # -loads via a second awaited SELECT as part of the parent query.
    contributions: Mapped[list[RiskProfileContributionModel]] = relationship(
        back_populates="profile",
        cascade="all, delete-orphan",
        order_by="RiskProfileContributionModel.ordinal",
        lazy="selectin",
    )
    score_history: Mapped[list[RiskProfileScoreHistoryModel]] = relationship(
        back_populates="profile",
        cascade="all, delete-orphan",
        order_by="RiskProfileScoreHistoryModel.computed_at",
        lazy="selectin",
    )

    __table_args__ = (
        Index("ix_risk_engine_profiles_tenant", "tenant_id"),
        Index("ix_risk_engine_profiles_tenant_status", "tenant_id", "status"),
        Index("ix_risk_engine_profiles_tenant_subject", "tenant_id", "subject_reference"),
    )


class RiskProfileContributionModel(Base):
    __tablename__ = "risk_engine_profile_contributions"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    profile_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("risk_engine_profiles.id", ondelete="CASCADE"),
        nullable=False,
    )
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)

    dimension: Mapped[str] = mapped_column(String(64), nullable=False)
    normalized_score: Mapped[float] = mapped_column(Float(), nullable=False)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Flattened RiskSignalReference — see risk_correlation_model.py for the
    # identical shape reused for correlation-set signal references.
    signal_tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    signal_source_context: Mapped[str] = mapped_column(String(128), nullable=False)
    signal_source_aggregate_type: Mapped[str] = mapped_column(String(128), nullable=False)
    signal_source_id: Mapped[str] = mapped_column(String(256), nullable=False)
    signal_type: Mapped[str] = mapped_column(String(64), nullable=False)
    signal_raw_value: Mapped[float] = mapped_column(Float(), nullable=False)
    signal_raw_scale: Mapped[str] = mapped_column(String(32), nullable=False)
    signal_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    signal_subject_reference: Mapped[str | None] = mapped_column(String(512), nullable=True)

    profile: Mapped[RiskProfileModel] = relationship(back_populates="contributions")

    __table_args__ = (
        Index("ix_risk_engine_profile_contributions_profile", "profile_id"),
        UniqueConstraint(
            "profile_id", "ordinal", name="uq_risk_engine_profile_contributions_ordinal"
        ),
    )


class RiskProfileScoreHistoryModel(Base):
    __tablename__ = "risk_engine_profile_score_history"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    profile_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("risk_engine_profiles.id", ondelete="CASCADE"),
        nullable=False,
    )
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    value: Mapped[float] = mapped_column(Float(), nullable=False)
    weight_profile_id: Mapped[str] = mapped_column(String(256), nullable=False)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    profile: Mapped[RiskProfileModel] = relationship(back_populates="score_history")

    __table_args__ = (
        Index("ix_risk_engine_profile_score_history_profile", "profile_id", "computed_at"),
        Index("ix_risk_engine_profile_score_history_tenant", "tenant_id"),
        UniqueConstraint(
            "profile_id",
            "computed_at",
            name="uq_risk_engine_profile_score_history_profile_computed_at",
        ),
    )
