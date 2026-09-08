"""ORM models for `Infrastructure`, mirroring
`tool_intel.infrastructure.persistence.models.tool_models`'s shape
exactly.

`InfrastructureModel.tenant_id` is nullable — `None` is a genuine global
RedForge-curated record, never a reserved sentinel. Identity is enforced
on `(tenant_id, infrastructure_type, normalized_identifier)` via two
partial unique indexes (global vs. tenant scope), the same
NULL-is-distinct-from-NULL-aware split `tool_intel` already
established — a plain UNIQUE over a nullable `tenant_id` would not
prevent unlimited duplicate global identities in PostgreSQL.

Single-valued facets (hosting provider, cloud provider, network
ownership) are columns on the parent row; genuinely repeating facets
(regions, evidence citations, source attributions, version history) are
owned child tables.

No relationship table exists here by design: cross-entity relationships
are owned exclusively by `intelligence_relationships`.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from redforge.infrastructure.database.base import Base


class InfrastructureModel(Base):
    __tablename__ = "infrastructure_intel_infrastructure"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    infrastructure_type: Mapped[str] = mapped_column(String(32), nullable=False)
    normalized_identifier: Mapped[str] = mapped_column(String(512), nullable=False)
    lifecycle_status: Mapped[str] = mapped_column(String(16), nullable=False)
    hosting_provider_name: Mapped[str | None] = mapped_column(String(300), nullable=True)
    cloud_provider: Mapped[str | None] = mapped_column(String(32), nullable=True)
    registrant_organization: Mapped[str | None] = mapped_column(String(300), nullable=True)
    abuse_contact: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    ownership_notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    superseded_by: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    regions: Mapped[list[InfrastructureRegionModel]] = relationship(
        back_populates="infrastructure", cascade="all, delete-orphan", lazy="selectin"
    )
    evidence_citations: Mapped[list[InfrastructureEvidenceCitationModel]] = relationship(
        back_populates="infrastructure", cascade="all, delete-orphan", lazy="selectin"
    )
    source_attributions: Mapped[list[InfrastructureSourceAttributionModel]] = relationship(
        back_populates="infrastructure", cascade="all, delete-orphan", lazy="selectin"
    )
    version_history: Mapped[list[InfrastructureVersionModel]] = relationship(
        back_populates="infrastructure", cascade="all, delete-orphan", lazy="selectin"
    )

    __table_args__ = (
        Index("ix_infrastructure_intel_tenant", "tenant_id"),
        Index("ix_infrastructure_intel_identifier", "normalized_identifier"),
        Index("ix_infrastructure_intel_lifecycle", "lifecycle_status"),
        Index("ix_infrastructure_intel_type", "infrastructure_type"),
        Index("ix_infrastructure_intel_cloud_provider", "cloud_provider"),
        Index(
            "uq_infrastructure_intel_global_identity",
            "infrastructure_type",
            "normalized_identifier",
            unique=True,
            postgresql_where=text("tenant_id IS NULL"),
        ),
        Index(
            "uq_infrastructure_intel_tenant_identity",
            "tenant_id",
            "infrastructure_type",
            "normalized_identifier",
            unique=True,
            postgresql_where=text("tenant_id IS NOT NULL"),
        ),
    )


class InfrastructureRegionModel(Base):
    __tablename__ = "infrastructure_intel_regions"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    infrastructure_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("infrastructure_intel_infrastructure.id", ondelete="CASCADE"),
        nullable=False,
    )
    region_code: Mapped[str] = mapped_column(String(128), nullable=False)

    infrastructure: Mapped[InfrastructureModel] = relationship(back_populates="regions")

    __table_args__ = (
        Index("ix_infrastructure_intel_regions_parent", "infrastructure_id"),
        Index(
            "uq_infrastructure_intel_regions_dedup",
            "infrastructure_id",
            "region_code",
            unique=True,
        ),
    )


class InfrastructureEvidenceCitationModel(Base):
    __tablename__ = "infrastructure_intel_evidence_citations"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    infrastructure_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("infrastructure_intel_infrastructure.id", ondelete="CASCADE"),
        nullable=False,
    )
    value: Mapped[str] = mapped_column(Text, nullable=False)

    infrastructure: Mapped[InfrastructureModel] = relationship(back_populates="evidence_citations")

    __table_args__ = (
        Index("ix_infrastructure_intel_evidence_citations_parent", "infrastructure_id"),
    )


class InfrastructureSourceAttributionModel(Base):
    __tablename__ = "infrastructure_intel_source_attributions"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    infrastructure_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("infrastructure_intel_infrastructure.id", ondelete="CASCADE"),
        nullable=False,
    )
    source_system: Mapped[str] = mapped_column(String(128), nullable=False)
    reference: Mapped[str] = mapped_column(String(512), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")

    infrastructure: Mapped[InfrastructureModel] = relationship(back_populates="source_attributions")

    __table_args__ = (
        Index("ix_infrastructure_intel_source_attributions_parent", "infrastructure_id"),
    )


class InfrastructureVersionModel(Base):
    __tablename__ = "infrastructure_intel_version_history"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    infrastructure_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("infrastructure_intel_infrastructure.id", ondelete="CASCADE"),
        nullable=False,
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    change_summary: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(128), nullable=False)

    infrastructure: Mapped[InfrastructureModel] = relationship(back_populates="version_history")

    __table_args__ = (
        Index("ix_infrastructure_intel_version_history_parent", "infrastructure_id"),
        Index(
            "uq_infrastructure_intel_version_history_dedup",
            "infrastructure_id",
            "version",
            unique=True,
        ),
    )
