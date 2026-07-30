"""ORM models for the `RiskCorrelationSet` aggregate (M48E).

Two tables: ``risk_engine_correlation_sets`` (the aggregate root) and
``risk_engine_correlation_signal_refs`` (child rows for its
`signal_references` tuple, ordered by `ordinal` to preserve the
original tuple order on rehydration — `RiskCorrelationSet` is
immutable once formed, so this child table is only ever written once,
at `save()` time for a brand-new aggregate; there is no update path).
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from redforge.infrastructure.database.base import Base


class RiskCorrelationSetModel(Base):
    __tablename__ = "risk_engine_correlation_sets"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    formed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # lazy="selectin": mandatory under AsyncSession — see
    # risk_profile_model.py's identical note.
    signal_references: Mapped[list[RiskCorrelationSignalRefModel]] = relationship(
        back_populates="correlation_set",
        cascade="all, delete-orphan",
        order_by="RiskCorrelationSignalRefModel.ordinal",
        lazy="selectin",
    )

    __table_args__ = (Index("ix_risk_engine_correlation_sets_tenant", "tenant_id"),)


class RiskCorrelationSignalRefModel(Base):
    __tablename__ = "risk_engine_correlation_signal_refs"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    correlation_set_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("risk_engine_correlation_sets.id", ondelete="CASCADE"),
        nullable=False,
    )
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)

    # Flattened RiskSignalReference — identical shape to
    # RiskProfileContributionModel's signal_* columns.
    signal_tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    signal_source_context: Mapped[str] = mapped_column(String(128), nullable=False)
    signal_source_aggregate_type: Mapped[str] = mapped_column(String(128), nullable=False)
    signal_source_id: Mapped[str] = mapped_column(String(256), nullable=False)
    signal_type: Mapped[str] = mapped_column(String(64), nullable=False)
    signal_raw_value: Mapped[float] = mapped_column(Float(), nullable=False)
    signal_raw_scale: Mapped[str] = mapped_column(String(32), nullable=False)
    signal_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    signal_subject_reference: Mapped[str | None] = mapped_column(String(512), nullable=True)

    correlation_set: Mapped[RiskCorrelationSetModel] = relationship(
        back_populates="signal_references"
    )

    __table_args__ = (
        Index("ix_risk_engine_correlation_signal_refs_set", "correlation_set_id"),
        UniqueConstraint(
            "correlation_set_id",
            "ordinal",
            name="uq_risk_engine_correlation_signal_refs_ordinal",
        ),
    )
