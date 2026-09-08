"""ORM models for `Campaign`, mirroring
`malware_intel.infrastructure.persistence.models.malware_models`'s shape
exactly.

`CampaignModel.tenant_id` is nullable — `None` is a genuine global
RedForge-curated record, never a reserved sentinel. Identity is enforced
on `(tenant_id, canonical_name)` via two partial unique indexes (global
vs. tenant scope), the same NULL-is-distinct-from-NULL-aware split
`malware_intel` already established — a plain
`UNIQUE(tenant_id, canonical_name)` would not prevent unlimited
duplicate global identities in PostgreSQL.

`status` (real-world campaign state) and `lifecycle_status` (RedForge
record lifecycle) are two separate, independently-indexed columns by
design — collapsing them into one would erase the distinction the domain
guarantees.

No relationship table exists here by design: cross-entity relationships
are owned exclusively by `intelligence_relationships`.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from redforge.infrastructure.database.base import Base


class CampaignModel(Base):
    __tablename__ = "campaign_intel_campaigns"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    canonical_name: Mapped[str] = mapped_column(String(300), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    lifecycle_status: Mapped[str] = mapped_column(String(16), nullable=False)
    motivation: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    timeline_first_observed: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    timeline_last_observed: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    timeline_ongoing: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    superseded_by: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    aliases: Mapped[list[CampaignAliasModel]] = relationship(
        back_populates="campaign", cascade="all, delete-orphan", lazy="selectin"
    )
    objectives: Mapped[list[CampaignObjectiveModel]] = relationship(
        back_populates="campaign", cascade="all, delete-orphan", lazy="selectin"
    )
    regions: Mapped[list[CampaignRegionModel]] = relationship(
        back_populates="campaign", cascade="all, delete-orphan", lazy="selectin"
    )
    target_sectors: Mapped[list[CampaignTargetSectorModel]] = relationship(
        back_populates="campaign", cascade="all, delete-orphan", lazy="selectin"
    )
    evidence_citations: Mapped[list[CampaignEvidenceCitationModel]] = relationship(
        back_populates="campaign", cascade="all, delete-orphan", lazy="selectin"
    )
    source_attributions: Mapped[list[CampaignSourceAttributionModel]] = relationship(
        back_populates="campaign", cascade="all, delete-orphan", lazy="selectin"
    )
    version_history: Mapped[list[CampaignVersionModel]] = relationship(
        back_populates="campaign", cascade="all, delete-orphan", lazy="selectin"
    )

    __table_args__ = (
        Index("ix_campaign_intel_campaigns_tenant", "tenant_id"),
        Index("ix_campaign_intel_campaigns_canonical_name", "canonical_name"),
        Index("ix_campaign_intel_campaigns_lifecycle", "lifecycle_status"),
        Index("ix_campaign_intel_campaigns_status", "status"),
        Index("ix_campaign_intel_campaigns_motivation", "motivation"),
        Index(
            "uq_campaign_intel_global_identity",
            "canonical_name",
            unique=True,
            postgresql_where=text("tenant_id IS NULL"),
        ),
        Index(
            "uq_campaign_intel_tenant_identity",
            "tenant_id",
            "canonical_name",
            unique=True,
            postgresql_where=text("tenant_id IS NOT NULL"),
        ),
    )


class CampaignAliasModel(Base):
    __tablename__ = "campaign_intel_aliases"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    campaign_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("campaign_intel_campaigns.id", ondelete="CASCADE"),
        nullable=False,
    )
    value: Mapped[str] = mapped_column(String(300), nullable=False)

    campaign: Mapped[CampaignModel] = relationship(back_populates="aliases")

    __table_args__ = (Index("ix_campaign_intel_aliases_campaign", "campaign_id"),)


class CampaignObjectiveModel(Base):
    __tablename__ = "campaign_intel_objectives"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    campaign_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("campaign_intel_campaigns.id", ondelete="CASCADE"),
        nullable=False,
    )
    objective_type: Mapped[str] = mapped_column(String(32), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")

    campaign: Mapped[CampaignModel] = relationship(back_populates="objectives")

    __table_args__ = (Index("ix_campaign_intel_objectives_campaign", "campaign_id"),)


class CampaignRegionModel(Base):
    __tablename__ = "campaign_intel_regions"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    campaign_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("campaign_intel_campaigns.id", ondelete="CASCADE"),
        nullable=False,
    )
    region: Mapped[str] = mapped_column(String(32), nullable=False)

    campaign: Mapped[CampaignModel] = relationship(back_populates="regions")

    __table_args__ = (
        Index("ix_campaign_intel_regions_campaign", "campaign_id"),
        Index("uq_campaign_intel_regions_dedup", "campaign_id", "region", unique=True),
    )


class CampaignTargetSectorModel(Base):
    __tablename__ = "campaign_intel_target_sectors"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    campaign_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("campaign_intel_campaigns.id", ondelete="CASCADE"),
        nullable=False,
    )
    target_sector: Mapped[str] = mapped_column(String(32), nullable=False)

    campaign: Mapped[CampaignModel] = relationship(back_populates="target_sectors")

    __table_args__ = (
        Index("ix_campaign_intel_target_sectors_campaign", "campaign_id"),
        Index(
            "uq_campaign_intel_target_sectors_dedup", "campaign_id", "target_sector", unique=True
        ),
    )


class CampaignEvidenceCitationModel(Base):
    __tablename__ = "campaign_intel_evidence_citations"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    campaign_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("campaign_intel_campaigns.id", ondelete="CASCADE"),
        nullable=False,
    )
    value: Mapped[str] = mapped_column(Text, nullable=False)

    campaign: Mapped[CampaignModel] = relationship(back_populates="evidence_citations")

    __table_args__ = (Index("ix_campaign_intel_evidence_citations_campaign", "campaign_id"),)


class CampaignSourceAttributionModel(Base):
    __tablename__ = "campaign_intel_source_attributions"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    campaign_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("campaign_intel_campaigns.id", ondelete="CASCADE"),
        nullable=False,
    )
    source_system: Mapped[str] = mapped_column(String(128), nullable=False)
    reference: Mapped[str] = mapped_column(String(512), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")

    campaign: Mapped[CampaignModel] = relationship(back_populates="source_attributions")

    __table_args__ = (Index("ix_campaign_intel_source_attributions_campaign", "campaign_id"),)


class CampaignVersionModel(Base):
    __tablename__ = "campaign_intel_version_history"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    campaign_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("campaign_intel_campaigns.id", ondelete="CASCADE"),
        nullable=False,
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    change_summary: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(128), nullable=False)

    campaign: Mapped[CampaignModel] = relationship(back_populates="version_history")

    __table_args__ = (
        Index("ix_campaign_intel_version_history_campaign", "campaign_id"),
        Index(
            "uq_campaign_intel_version_history_dedup",
            "campaign_id",
            "version",
            unique=True,
        ),
    )
