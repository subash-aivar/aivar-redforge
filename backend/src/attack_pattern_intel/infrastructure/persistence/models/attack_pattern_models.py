"""ORM models for `AttackPattern` (M51.3 Phase B1), mirroring
`ioc_intelligence.infrastructure.persistence.models.ioc_models`'s
shape exactly.

`AttackPatternModel.tenant_id` is nullable — `None` is a genuine
global RedForge-curated record, never a reserved sentinel. Identity is
enforced on `(tenant_id, technique_id, sub_technique_id)` via two
partial unique indexes (global vs. tenant scope), the same
NULL-is-distinct-from-NULL-aware split `ioc_intelligence` already
established — a plain `UNIQUE(tenant_id, technique_id, ...)` would not
prevent unlimited duplicate global identities in PostgreSQL.

These models do NOT reference or alter `attack_techniques`/
`attack_tactics` (M22, DO-NOT-MODIFY) — `technique_id`/
`sub_technique_id` are plain string columns, validated for existence
in the canonical catalog only at the application layer via
`IMitreTechniqueIdentityPort`, never via a DB-level foreign key across
bounded contexts."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from redforge.infrastructure.database.base import Base


class AttackPatternModel(Base):
    __tablename__ = "attack_pattern_intel_patterns"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False)
    sub_technique_id: Mapped[str | None] = mapped_column(String(20), nullable=True)
    lifecycle_status: Mapped[str] = mapped_column(String(16), nullable=False)
    superseded_by: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    tactic_mappings: Mapped[list[dict[str, object]]] = mapped_column(
        JSON, nullable=False, default=list
    )
    platforms: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    detection_guidance: Mapped[list[AttackPatternDetectionGuidanceModel]] = relationship(
        back_populates="pattern", cascade="all, delete-orphan", lazy="selectin"
    )
    mitigation_references: Mapped[list[AttackPatternMitigationReferenceModel]] = relationship(
        back_populates="pattern", cascade="all, delete-orphan", lazy="selectin"
    )
    procedure_examples: Mapped[list[AttackPatternProcedureExampleModel]] = relationship(
        back_populates="pattern", cascade="all, delete-orphan", lazy="selectin"
    )
    relationship_metadata: Mapped[list[AttackPatternRelationshipModel]] = relationship(
        back_populates="pattern", cascade="all, delete-orphan", lazy="selectin"
    )
    version_history: Mapped[list[AttackPatternVersionModel]] = relationship(
        back_populates="pattern", cascade="all, delete-orphan", lazy="selectin"
    )

    __table_args__ = (
        Index("ix_attack_pattern_intel_patterns_tenant", "tenant_id"),
        Index("ix_attack_pattern_intel_patterns_technique_id", "technique_id"),
        Index("ix_attack_pattern_intel_patterns_lifecycle", "lifecycle_status"),
        Index(
            "uq_attack_pattern_intel_global_identity",
            "technique_id",
            "sub_technique_id",
            unique=True,
            postgresql_where=text("tenant_id IS NULL"),
        ),
        Index(
            "uq_attack_pattern_intel_tenant_identity",
            "tenant_id",
            "technique_id",
            "sub_technique_id",
            unique=True,
            postgresql_where=text("tenant_id IS NOT NULL"),
        ),
    )


class AttackPatternDetectionGuidanceModel(Base):
    __tablename__ = "attack_pattern_intel_detection_guidance"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    attack_pattern_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("attack_pattern_intel_patterns.id", ondelete="CASCADE"),
        nullable=False,
    )
    content: Mapped[str] = mapped_column(Text, nullable=False)
    source_system: Mapped[str] = mapped_column(String(128), nullable=False)
    reference: Mapped[str] = mapped_column(String(512), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")

    pattern: Mapped[AttackPatternModel] = relationship(back_populates="detection_guidance")

    __table_args__ = (
        Index("ix_attack_pattern_intel_detection_guidance_pattern", "attack_pattern_id"),
    )


class AttackPatternMitigationReferenceModel(Base):
    __tablename__ = "attack_pattern_intel_mitigation_references"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    attack_pattern_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("attack_pattern_intel_patterns.id", ondelete="CASCADE"),
        nullable=False,
    )
    mitigation_id: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    source_system: Mapped[str] = mapped_column(String(128), nullable=False)
    reference: Mapped[str] = mapped_column(String(512), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")

    pattern: Mapped[AttackPatternModel] = relationship(back_populates="mitigation_references")

    __table_args__ = (
        Index("ix_attack_pattern_intel_mitigation_references_pattern", "attack_pattern_id"),
    )


class AttackPatternProcedureExampleModel(Base):
    __tablename__ = "attack_pattern_intel_procedure_examples"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    attack_pattern_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("attack_pattern_intel_patterns.id", ondelete="CASCADE"),
        nullable=False,
    )
    description: Mapped[str] = mapped_column(Text, nullable=False)
    actor_ref: Mapped[str | None] = mapped_column(String(300), nullable=True)
    source_system: Mapped[str] = mapped_column(String(128), nullable=False)
    reference: Mapped[str] = mapped_column(String(512), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")

    pattern: Mapped[AttackPatternModel] = relationship(back_populates="procedure_examples")

    __table_args__ = (
        Index("ix_attack_pattern_intel_procedure_examples_pattern", "attack_pattern_id"),
    )


class AttackPatternRelationshipModel(Base):
    __tablename__ = "attack_pattern_intel_relationships"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    attack_pattern_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("attack_pattern_intel_patterns.id", ondelete="CASCADE"),
        nullable=False,
    )
    relationship_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_attack_pattern_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    source_system: Mapped[str] = mapped_column(String(128), nullable=False)
    reference: Mapped[str] = mapped_column(String(512), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")

    pattern: Mapped[AttackPatternModel] = relationship(back_populates="relationship_metadata")

    __table_args__ = (Index("ix_attack_pattern_intel_relationships_pattern", "attack_pattern_id"),)


class AttackPatternVersionModel(Base):
    __tablename__ = "attack_pattern_intel_version_history"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    attack_pattern_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("attack_pattern_intel_patterns.id", ondelete="CASCADE"),
        nullable=False,
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    change_summary: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(128), nullable=False)

    pattern: Mapped[AttackPatternModel] = relationship(back_populates="version_history")

    __table_args__ = (
        Index("ix_attack_pattern_intel_version_history_pattern", "attack_pattern_id"),
        Index(
            "uq_attack_pattern_intel_version_history_dedup",
            "attack_pattern_id",
            "version",
            unique=True,
        ),
    )
