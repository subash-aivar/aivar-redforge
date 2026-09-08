"""ORM models for `ThreatActor` and `ThreatActorAssociation` (M51.1
Phase 3).

`ThreatActorModel.tenant_id` is nullable — the concrete, DB-level
expression of ADR-M51.1-02: `None` is a genuine global reference
record, not a reserved sentinel. `motivations` is denormalized onto
the aggregate-root row as JSON (a `frozenset[MotivationType]` has no
per-item metadata worth a child table, unlike aliases/techniques/
indicators, which the M51.1 Phase 3 scope explicitly names as their
own tables).

`ThreatActorAssociationModel.tenant_id` is NOT NULL — associations are
always tenant-scoped (ADR-M51.1-03). A partial unique index enforces
`AssociationUniquenessPolicy`'s invariant at the database level too:
exactly one `ACTIVE` row per `(tenant_id, threat_actor_id,
referenced_entity_type, referenced_entity_id)` — defense in depth
alongside the application-layer policy check, not a replacement for
it (a concurrent writer racing the application-layer check is still
caught here)."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, text
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from redforge.infrastructure.database.base import Base


class ThreatActorModel(Base):
    __tablename__ = "threat_actor_intel_threat_actors"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    origin: Mapped[str] = mapped_column(String(32), nullable=False)
    sophistication: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    attribution_confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    motivations: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    aliases: Mapped[list[ThreatActorAliasModel]] = relationship(
        back_populates="threat_actor",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    techniques: Mapped[list[ThreatActorTechniqueModel]] = relationship(
        back_populates="threat_actor",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    indicators: Mapped[list[ThreatActorIndicatorModel]] = relationship(
        back_populates="threat_actor",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    __table_args__ = (
        Index("ix_threat_actor_intel_threat_actors_tenant", "tenant_id"),
        Index("ix_threat_actor_intel_threat_actors_status", "status"),
        Index("ix_threat_actor_intel_threat_actors_origin", "origin"),
    )


class ThreatActorAliasModel(Base):
    __tablename__ = "threat_actor_intel_threat_actor_aliases"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    threat_actor_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("threat_actor_intel_threat_actors.id", ondelete="CASCADE"),
        nullable=False,
    )
    alias: Mapped[str] = mapped_column(String(512), nullable=False)

    threat_actor: Mapped[ThreatActorModel] = relationship(back_populates="aliases")

    __table_args__ = (Index("ix_threat_actor_intel_threat_actor_aliases_actor", "threat_actor_id"),)


class ThreatActorTechniqueModel(Base):
    __tablename__ = "threat_actor_intel_threat_actor_techniques"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    threat_actor_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("threat_actor_intel_threat_actors.id", ondelete="CASCADE"),
        nullable=False,
    )
    technique_id: Mapped[str] = mapped_column(String(64), nullable=False)

    threat_actor: Mapped[ThreatActorModel] = relationship(back_populates="techniques")

    __table_args__ = (
        Index("ix_threat_actor_intel_threat_actor_techniques_actor", "threat_actor_id"),
        Index(
            "uq_threat_actor_intel_threat_actor_techniques_actor_technique",
            "threat_actor_id",
            "technique_id",
            unique=True,
        ),
    )


class ThreatActorIndicatorModel(Base):
    __tablename__ = "threat_actor_intel_threat_actor_indicators"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    threat_actor_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("threat_actor_intel_threat_actors.id", ondelete="CASCADE"),
        nullable=False,
    )
    indicator_id: Mapped[str] = mapped_column(String(256), nullable=False)

    threat_actor: Mapped[ThreatActorModel] = relationship(back_populates="indicators")

    __table_args__ = (
        Index("ix_threat_actor_intel_threat_actor_indicators_actor", "threat_actor_id"),
        Index(
            "uq_threat_actor_intel_threat_actor_indicators_actor_indicator",
            "threat_actor_id",
            "indicator_id",
            unique=True,
        ),
    )


class ThreatActorAssociationModel(Base):
    __tablename__ = "threat_actor_intel_associations"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    threat_actor_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("threat_actor_intel_threat_actors.id"),
        nullable=False,
    )
    referenced_entity_type: Mapped[str] = mapped_column(String(256), nullable=False)
    referenced_entity_id: Mapped[str] = mapped_column(String(512), nullable=False)
    evidence_citation: Mapped[str] = mapped_column(String(2048), nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    retracted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_threat_actor_intel_associations_tenant", "tenant_id"),
        Index(
            "ix_threat_actor_intel_associations_tenant_actor",
            "tenant_id",
            "threat_actor_id",
        ),
        Index(
            "uq_threat_actor_intel_associations_active_tuple",
            "tenant_id",
            "threat_actor_id",
            "referenced_entity_type",
            "referenced_entity_id",
            unique=True,
            postgresql_where=text("state = 'active'"),
        ),
    )
