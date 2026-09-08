"""ORM models for `Tool`, mirroring
`campaign_intel.infrastructure.persistence.models.campaign_models`'s
shape exactly.

`ToolModel.tenant_id` is nullable — `None` is a genuine global
RedForge-curated record, never a reserved sentinel. Identity is enforced
on `(tenant_id, canonical_name)` via two partial unique indexes (global
vs. tenant scope), the same NULL-is-distinct-from-NULL-aware split
`campaign_intel` already established — a plain
`UNIQUE(tenant_id, canonical_name)` would not prevent unlimited
duplicate global identities in PostgreSQL.

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


class ToolModel(Base):
    __tablename__ = "tool_intel_tools"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    canonical_name: Mapped[str] = mapped_column(String(300), nullable=False)
    category: Mapped[str] = mapped_column(String(48), nullable=False)
    lifecycle_status: Mapped[str] = mapped_column(String(16), nullable=False)
    family_name: Mapped[str | None] = mapped_column(String(300), nullable=True)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    superseded_by: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    aliases: Mapped[list[ToolAliasModel]] = relationship(
        back_populates="tool", cascade="all, delete-orphan", lazy="selectin"
    )
    platforms: Mapped[list[ToolPlatformModel]] = relationship(
        back_populates="tool", cascade="all, delete-orphan", lazy="selectin"
    )
    capabilities: Mapped[list[ToolCapabilityModel]] = relationship(
        back_populates="tool", cascade="all, delete-orphan", lazy="selectin"
    )
    evidence_citations: Mapped[list[ToolEvidenceCitationModel]] = relationship(
        back_populates="tool", cascade="all, delete-orphan", lazy="selectin"
    )
    source_attributions: Mapped[list[ToolSourceAttributionModel]] = relationship(
        back_populates="tool", cascade="all, delete-orphan", lazy="selectin"
    )
    version_history: Mapped[list[ToolVersionModel]] = relationship(
        back_populates="tool", cascade="all, delete-orphan", lazy="selectin"
    )

    __table_args__ = (
        Index("ix_tool_intel_tools_tenant", "tenant_id"),
        Index("ix_tool_intel_tools_canonical_name", "canonical_name"),
        Index("ix_tool_intel_tools_lifecycle", "lifecycle_status"),
        Index("ix_tool_intel_tools_category", "category"),
        Index("ix_tool_intel_tools_family", "family_name"),
        Index(
            "uq_tool_intel_global_identity",
            "canonical_name",
            unique=True,
            postgresql_where=text("tenant_id IS NULL"),
        ),
        Index(
            "uq_tool_intel_tenant_identity",
            "tenant_id",
            "canonical_name",
            unique=True,
            postgresql_where=text("tenant_id IS NOT NULL"),
        ),
    )


class ToolAliasModel(Base):
    __tablename__ = "tool_intel_aliases"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tool_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("tool_intel_tools.id", ondelete="CASCADE"),
        nullable=False,
    )
    value: Mapped[str] = mapped_column(String(300), nullable=False)

    tool: Mapped[ToolModel] = relationship(back_populates="aliases")

    __table_args__ = (Index("ix_tool_intel_aliases_tool", "tool_id"),)


class ToolPlatformModel(Base):
    __tablename__ = "tool_intel_platforms"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tool_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("tool_intel_tools.id", ondelete="CASCADE"),
        nullable=False,
    )
    platform: Mapped[str] = mapped_column(String(32), nullable=False)

    tool: Mapped[ToolModel] = relationship(back_populates="platforms")

    __table_args__ = (
        Index("ix_tool_intel_platforms_tool", "tool_id"),
        Index("uq_tool_intel_platforms_dedup", "tool_id", "platform", unique=True),
    )


class ToolCapabilityModel(Base):
    __tablename__ = "tool_intel_capabilities"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tool_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("tool_intel_tools.id", ondelete="CASCADE"),
        nullable=False,
    )
    capability: Mapped[str] = mapped_column(String(32), nullable=False)

    tool: Mapped[ToolModel] = relationship(back_populates="capabilities")

    __table_args__ = (
        Index("ix_tool_intel_capabilities_tool", "tool_id"),
        Index("uq_tool_intel_capabilities_dedup", "tool_id", "capability", unique=True),
    )


class ToolEvidenceCitationModel(Base):
    __tablename__ = "tool_intel_evidence_citations"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tool_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("tool_intel_tools.id", ondelete="CASCADE"),
        nullable=False,
    )
    value: Mapped[str] = mapped_column(Text, nullable=False)

    tool: Mapped[ToolModel] = relationship(back_populates="evidence_citations")

    __table_args__ = (Index("ix_tool_intel_evidence_citations_tool", "tool_id"),)


class ToolSourceAttributionModel(Base):
    __tablename__ = "tool_intel_source_attributions"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tool_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("tool_intel_tools.id", ondelete="CASCADE"),
        nullable=False,
    )
    source_system: Mapped[str] = mapped_column(String(128), nullable=False)
    reference: Mapped[str] = mapped_column(String(512), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")

    tool: Mapped[ToolModel] = relationship(back_populates="source_attributions")

    __table_args__ = (Index("ix_tool_intel_source_attributions_tool", "tool_id"),)


class ToolVersionModel(Base):
    __tablename__ = "tool_intel_version_history"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tool_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("tool_intel_tools.id", ondelete="CASCADE"),
        nullable=False,
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    change_summary: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(128), nullable=False)

    tool: Mapped[ToolModel] = relationship(back_populates="version_history")

    __table_args__ = (
        Index("ix_tool_intel_version_history_tool", "tool_id"),
        Index("uq_tool_intel_version_history_dedup", "tool_id", "version", unique=True),
    )
