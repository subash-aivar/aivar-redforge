"""ORM models for the Investigation bounded context — M21.

Four tables:
  investigations              — case aggregate with lifecycle + versioning
  investigation_evidence_links — case-to-source-evidence mapping (idempotent)
  investigation_events        — append-only timeline entries
  investigation_correlation_cursors — per-source worker watermarks
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base


class InvestigationModel(Base):
    """Cross-domain investigation case with optimistic concurrency versioning.

    correlation_key enforces exactly-one-active-investigation per key
    via a partial unique index on non-RESOLVED statuses, matching the
    DDoS/behavior advisory-lock + partial-index pattern from M19/M20.
    """

    __tablename__ = "investigations"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="ux_inv_id_org"),
        Index("ix_inv_org_status", "organization_id", "status"),
        Index("ix_inv_org_severity", "organization_id", "severity"),
        Index("ix_inv_org_opened", "organization_id", "opened_at"),
        Index("ix_inv_org_updated", "organization_id", "updated_at"),
        # Partial unique index: one active investigation per correlation_key
        Index(
            "ux_inv_org_corr_active",
            "organization_id", "correlation_key",
            unique=True,
            postgresql_where=text("status != 'RESOLVED'"),
        ),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="OPEN")
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    confidence: Mapped[str] = mapped_column(String(20), nullable=False)
    correlation_key: Mapped[str] = mapped_column(String(600), nullable=False)

    # Source domains and entities stored as JSON arrays
    source_domains: Mapped[list[str] | None] = mapped_column(
        JSON, nullable=False, default=list
    )
    involved_entities: Mapped[list[dict[str, str]] | None] = mapped_column(
        JSON, nullable=False, default=list
    )
    evidence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Timeline anchors
    first_observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    opened_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    # Lifecycle timestamps (nullable until reached)
    acknowledged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    investigating_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    resolution_reason: Mapped[str | None] = mapped_column(String(60), nullable=True)
    resolution_notes: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # Optimistic concurrency version — bump on every state-changing write
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class InvestigationEvidenceLinkModel(Base):
    """Normalized reference to source-domain evidence.

    dedup_key is the stable idempotency anchor — same evidence row from
    the source domain always maps to the same dedup_key, preventing
    duplicate membership even under concurrent worker replay.
    """

    __tablename__ = "investigation_evidence_links"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "case_id", "dedup_key",
            name="ux_iel_org_case_dedup",
        ),
        Index("ix_iel_org_case", "organization_id", "case_id"),
        Index("ix_iel_org_domain", "organization_id", "source_domain"),
        Index("ix_iel_case_observed", "case_id", "observed_at"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    case_id: Mapped[str] = mapped_column(String(26), nullable=False)

    # Source-domain identity
    source_domain: Mapped[str] = mapped_column(String(40), nullable=False)
    source_entity_type: Mapped[str] = mapped_column(String(80), nullable=False)
    source_entity_id: Mapped[str] = mapped_column(String(200), nullable=False)
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)

    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    # Bounded metadata — never the full source row
    evidence_snapshot: Mapped[dict[str, Any] | None] = mapped_column(
        JSON, nullable=True, default=dict
    )
    correlation_reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    relationship_type: Mapped[str] = mapped_column(
        String(20), nullable=False, default="DIRECT"
    )
    observability: Mapped[str] = mapped_column(
        String(20), nullable=False, default="OBSERVED"
    )

    dedup_key: Mapped[str] = mapped_column(String(300), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class InvestigationEventModel(Base):
    """Append-only timeline entry for an investigation case.

    event_id is a stable dedup anchor — same lifecycle transition at the
    same wall-clock instant won't produce duplicates on replay.
    """

    __tablename__ = "investigation_events"
    __table_args__ = (
        UniqueConstraint("event_id", name="ux_iev_event_id"),
        Index("ix_iev_case", "case_id"),
        Index("ix_iev_org_ts", "organization_id", "occurred_at"),
        Index("ix_iev_org_type", "organization_id", "event_type"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    event_id: Mapped[str] = mapped_column(String(100), nullable=False)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    case_id: Mapped[str] = mapped_column(String(26), nullable=False)
    event_type: Mapped[str] = mapped_column(String(60), nullable=False)
    detail: Mapped[dict[str, Any] | None] = mapped_column(
        JSON, nullable=True, default=dict
    )
    actor_user_id: Mapped[str | None] = mapped_column(String(26), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class CorrelationCursorModel(Base):
    """Per-source-domain worker processing cursor.

    Stores the last-processed event position for each source domain so
    the correlation worker processes incrementally, not from scratch.
    """

    __tablename__ = "investigation_correlation_cursors"
    __table_args__ = (
        UniqueConstraint("source_domain", name="ux_icc_source_domain"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    source_domain: Mapped[str] = mapped_column(String(40), nullable=False)
    last_processed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_processed_id: Mapped[str] = mapped_column(String(200), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
