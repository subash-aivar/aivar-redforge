"""ORM models for `ThreatReport`, mirroring
`infrastructure_intel.infrastructure.persistence.models.
infrastructure_models`'s shape exactly.

`ThreatReportModel.tenant_id` is nullable — `None` is a genuine global
RedForge-curated record, never a reserved sentinel. Identity is
enforced on `(tenant_id, canonical_title)` via two partial unique
indexes (global vs. tenant scope), the same
NULL-is-distinct-from-NULL-aware split `infrastructure_intel` already
established — a plain UNIQUE over a nullable `tenant_id` would not
prevent unlimited duplicate global identities in PostgreSQL.

`title` (the analyst's real display value) and `canonical_title` (the
normalized dedup key) are two separate columns: only the latter is
indexed for uniqueness.

Single-valued facets (publisher, publication date, report metadata,
severity, confidence, the two summaries) are columns on the parent row;
genuinely repeating facets (references, evidence citations, source
attributions, version history) are owned child tables.

No relationship table exists here by design: cross-entity relationships
are owned exclusively by `intelligence_relationships`, which (as of
M51.9 Phase H1) defines `THREAT_REPORT_TO_*` `RelationshipType` values
with their own persistence there. Adding a relationship table here
would duplicate a certified capability, not fill a gap — see the
aggregate's module docstring for the full picture.
"""

from __future__ import annotations

from datetime import date, datetime
from uuid import UUID

from sqlalchemy import Date, DateTime, ForeignKey, Index, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from redforge.infrastructure.database.base import Base


class ThreatReportModel(Base):
    __tablename__ = "threat_report_intel_reports"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    canonical_title: Mapped[str] = mapped_column(String(512), nullable=False)
    publisher_organization_name: Mapped[str] = mapped_column(String(300), nullable=False)
    publisher_contact: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    publication_date: Mapped[date] = mapped_column(Date(), nullable=False)
    report_type: Mapped[str] = mapped_column(String(64), nullable=False)
    tlp_marking: Mapped[str] = mapped_column(String(32), nullable=False)
    external_report_id: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    executive_summary: Mapped[str] = mapped_column(Text, nullable=False)
    technical_summary: Mapped[str] = mapped_column(Text, nullable=False)
    lifecycle_status: Mapped[str] = mapped_column(String(16), nullable=False)
    superseded_by: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    references: Mapped[list[ThreatReportReferenceModel]] = relationship(
        back_populates="report", cascade="all, delete-orphan", lazy="selectin"
    )
    evidence_citations: Mapped[list[ThreatReportEvidenceCitationModel]] = relationship(
        back_populates="report", cascade="all, delete-orphan", lazy="selectin"
    )
    source_attributions: Mapped[list[ThreatReportSourceAttributionModel]] = relationship(
        back_populates="report", cascade="all, delete-orphan", lazy="selectin"
    )
    version_history: Mapped[list[ThreatReportVersionModel]] = relationship(
        back_populates="report", cascade="all, delete-orphan", lazy="selectin"
    )

    __table_args__ = (
        Index("ix_threat_report_intel_tenant", "tenant_id"),
        Index("ix_threat_report_intel_canonical_title", "canonical_title"),
        Index("ix_threat_report_intel_lifecycle", "lifecycle_status"),
        Index("ix_threat_report_intel_severity", "severity"),
        Index("ix_threat_report_intel_tlp", "tlp_marking"),
        Index("ix_threat_report_intel_publication_date", "publication_date"),
        Index(
            "uq_threat_report_intel_global_identity",
            "canonical_title",
            unique=True,
            postgresql_where=text("tenant_id IS NULL"),
        ),
        Index(
            "uq_threat_report_intel_tenant_identity",
            "tenant_id",
            "canonical_title",
            unique=True,
            postgresql_where=text("tenant_id IS NOT NULL"),
        ),
    )


class ThreatReportReferenceModel(Base):
    __tablename__ = "threat_report_intel_references"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    threat_report_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("threat_report_intel_reports.id", ondelete="CASCADE"),
        nullable=False,
    )
    url_or_citation: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")

    report: Mapped[ThreatReportModel] = relationship(back_populates="references")

    __table_args__ = (Index("ix_threat_report_intel_references_parent", "threat_report_id"),)


class ThreatReportEvidenceCitationModel(Base):
    __tablename__ = "threat_report_intel_evidence_citations"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    threat_report_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("threat_report_intel_reports.id", ondelete="CASCADE"),
        nullable=False,
    )
    value: Mapped[str] = mapped_column(Text, nullable=False)

    report: Mapped[ThreatReportModel] = relationship(back_populates="evidence_citations")

    __table_args__ = (
        Index("ix_threat_report_intel_evidence_citations_parent", "threat_report_id"),
    )


class ThreatReportSourceAttributionModel(Base):
    __tablename__ = "threat_report_intel_source_attributions"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    threat_report_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("threat_report_intel_reports.id", ondelete="CASCADE"),
        nullable=False,
    )
    source_system: Mapped[str] = mapped_column(String(128), nullable=False)
    reference: Mapped[str] = mapped_column(String(512), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")

    report: Mapped[ThreatReportModel] = relationship(back_populates="source_attributions")

    __table_args__ = (
        Index("ix_threat_report_intel_source_attributions_parent", "threat_report_id"),
    )


class ThreatReportVersionModel(Base):
    __tablename__ = "threat_report_intel_version_history"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    threat_report_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("threat_report_intel_reports.id", ondelete="CASCADE"),
        nullable=False,
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    change_summary: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(128), nullable=False)

    report: Mapped[ThreatReportModel] = relationship(back_populates="version_history")

    __table_args__ = (
        Index("ix_threat_report_intel_version_history_parent", "threat_report_id"),
        Index(
            "uq_threat_report_intel_version_history_dedup",
            "threat_report_id",
            "version",
            unique=True,
        ),
    )
