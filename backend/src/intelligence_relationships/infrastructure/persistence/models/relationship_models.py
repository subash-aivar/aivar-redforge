"""ORM models for `IntelligenceRelationship` (M51.4 Phase C1),
mirroring `attack_pattern_intel.infrastructure.persistence.models.
attack_pattern_models`'s child-table shape exactly.

`IntelligenceRelationshipModel.tenant_id` is nullable — `None` is a
genuine global RedForge-curated record, never a reserved sentinel.
Identity is enforced on
`(tenant_id, relationship_type, source_entity_type, source_entity_id,
target_entity_type, target_entity_id)` via two partial unique indexes
(global vs. tenant scope), the same
NULL-is-distinct-from-NULL-aware split `ioc_intelligence` and
`attack_pattern_intel` already established — a plain
`UNIQUE(tenant_id, ...)` would not prevent unlimited duplicate global
identities in PostgreSQL.

Endpoint columns are plain strings: NO foreign key crosses a bounded
context boundary into `ioc_intelligence_iocs`,
`threat_actor_intel_threat_actors`, or
`attack_pattern_intel_patterns`. Existence is checked at the
application layer via the read-only ACL ports only.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from redforge.infrastructure.database.base import Base


class IntelligenceRelationshipModel(Base):
    __tablename__ = "intelligence_relationships"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    relationship_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source_entity_type: Mapped[str] = mapped_column(String(32), nullable=False)
    source_entity_id: Mapped[str] = mapped_column(String(512), nullable=False)
    target_entity_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target_entity_id: Mapped[str] = mapped_column(String(512), nullable=False)
    direction: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    epistemic_state: Mapped[str] = mapped_column(String(16), nullable=False)
    lifecycle_status: Mapped[str] = mapped_column(String(16), nullable=False)
    superseded_by: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    evidence_citations: Mapped[list[IntelligenceRelationshipEvidenceCitationModel]] = relationship(
        back_populates="parent", cascade="all, delete-orphan", lazy="selectin"
    )
    source_attributions: Mapped[list[IntelligenceRelationshipSourceAttributionModel]] = (
        relationship(back_populates="parent", cascade="all, delete-orphan", lazy="selectin")
    )
    version_history: Mapped[list[IntelligenceRelationshipVersionModel]] = relationship(
        back_populates="parent", cascade="all, delete-orphan", lazy="selectin"
    )

    __table_args__ = (
        Index("ix_intelligence_relationships_tenant", "tenant_id"),
        Index("ix_intelligence_relationships_type", "relationship_type"),
        Index("ix_intelligence_relationships_lifecycle", "lifecycle_status"),
        Index("ix_intelligence_relationships_epistemic", "epistemic_state"),
        Index("ix_intelligence_relationships_source_entity", "source_entity_id"),
        Index("ix_intelligence_relationships_target_entity", "target_entity_id"),
        Index(
            "uq_intelligence_relationships_global_identity",
            "relationship_type",
            "source_entity_type",
            "source_entity_id",
            "target_entity_type",
            "target_entity_id",
            unique=True,
            postgresql_where=text("tenant_id IS NULL"),
        ),
        Index(
            "uq_intelligence_relationships_tenant_identity",
            "tenant_id",
            "relationship_type",
            "source_entity_type",
            "source_entity_id",
            "target_entity_type",
            "target_entity_id",
            unique=True,
            postgresql_where=text("tenant_id IS NOT NULL"),
        ),
    )


class IntelligenceRelationshipEvidenceCitationModel(Base):
    __tablename__ = "intelligence_relationship_evidence_citations"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    relationship_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("intelligence_relationships.id", ondelete="CASCADE"),
        nullable=False,
    )
    value: Mapped[str] = mapped_column(Text, nullable=False)
    position: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    parent: Mapped[IntelligenceRelationshipModel] = relationship(
        back_populates="evidence_citations"
    )

    __table_args__ = (
        Index("ix_intelligence_relationship_evidence_citations_parent", "relationship_id"),
    )


class IntelligenceRelationshipSourceAttributionModel(Base):
    __tablename__ = "intelligence_relationship_source_attributions"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    relationship_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("intelligence_relationships.id", ondelete="CASCADE"),
        nullable=False,
    )
    source_system: Mapped[str] = mapped_column(String(128), nullable=False)
    reference: Mapped[str] = mapped_column(String(512), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    position: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    parent: Mapped[IntelligenceRelationshipModel] = relationship(
        back_populates="source_attributions"
    )

    __table_args__ = (
        Index("ix_intelligence_relationship_source_attributions_parent", "relationship_id"),
    )


class IntelligenceRelationshipVersionModel(Base):
    __tablename__ = "intelligence_relationship_version_history"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    relationship_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("intelligence_relationships.id", ondelete="CASCADE"),
        nullable=False,
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    change_summary: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(128), nullable=False)

    parent: Mapped[IntelligenceRelationshipModel] = relationship(back_populates="version_history")

    __table_args__ = (
        Index("ix_intelligence_relationship_version_history_parent", "relationship_id"),
        Index(
            "uq_intelligence_relationship_version_history_dedup",
            "relationship_id",
            "version",
            unique=True,
        ),
    )
