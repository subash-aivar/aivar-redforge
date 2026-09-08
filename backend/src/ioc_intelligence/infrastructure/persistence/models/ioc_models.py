"""ORM models for `IOC` (M51.2 Phase A3), mirroring
`threat_actor_intel.infrastructure.persistence.models.
threat_actor_models`'s shape exactly.

`IocModel.tenant_id` is nullable — the concrete, DB-level expression
of the IOC domain's global-vs-tenant ownership model: `None` is a
genuine global reference record, never a reserved sentinel.

`canonical_key` is NOT persisted as its own column — it is fully
derivable from `(ioc_type, normalized_value)`, so storing it too would
be a duplicated computed value. The dedup identity is instead enforced
directly on `(ioc_type, normalized_value)`, scoped by ownership via
two partial unique indexes (see module docstring on the migration):
PostgreSQL's NULL-is-distinct-from-NULL unique-constraint semantics
mean a plain `UNIQUE(tenant_id, ioc_type, normalized_value)` would
silently allow unlimited duplicate *global* (`tenant_id IS NULL`)
identities — the partial-index split below is what actually prevents
that."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, text
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from redforge.infrastructure.database.base import Base


class IocModel(Base):
    __tablename__ = "ioc_intelligence_iocs"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    ioc_type: Mapped[str] = mapped_column(String(20), nullable=False)
    normalized_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    lifecycle: Mapped[str] = mapped_column(String(16), nullable=False)
    epistemic_state: Mapped[str] = mapped_column(String(16), nullable=False)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    source_attributions: Mapped[list[IocSourceAttributionModel]] = relationship(
        back_populates="ioc",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    evidence_citations: Mapped[list[IocEvidenceCitationModel]] = relationship(
        back_populates="ioc",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    __table_args__ = (
        Index("ix_ioc_intelligence_iocs_tenant", "tenant_id"),
        Index("ix_ioc_intelligence_iocs_ioc_type", "ioc_type"),
        Index("ix_ioc_intelligence_iocs_lifecycle", "lifecycle"),
        Index("ix_ioc_intelligence_iocs_epistemic_state", "epistemic_state"),
        Index("ix_ioc_intelligence_iocs_valid_until", "valid_until"),
        # M51.2 Slice 2.1 — added on EXPLAIN ANALYZE evidence against a
        # 50k-row seeded dataset: sorting a tenant-scoped list by
        # `lifecycle` or `valid_until` without these composite indexes
        # backward-scans the GLOBAL single-column index above and
        # filters out every other tenant's rows post-scan (measured:
        # ~8-19k rows discarded per page, 9-25ms) — a cost that grows
        # with total platform row count, not with this tenant's own
        # row count. `(tenant_id, lifecycle)`/`(tenant_id, valid_until)`
        # let the planner satisfy tenant-scope + sort order from one
        # index directly. Not added speculatively: `ioc_type`,
        # `epistemic_state`, and `created_at`/`updated_at` sorts were
        # measured fast (1-3ms) via the existing tenant-identity /
        # tenant indexes and get no new index here.
        Index("ix_ioc_intelligence_iocs_tenant_lifecycle", "tenant_id", "lifecycle"),
        Index("ix_ioc_intelligence_iocs_tenant_valid_until", "tenant_id", "valid_until"),
        # Global identity: at most one row per (ioc_type, normalized_value)
        # when tenant_id IS NULL. A plain UNIQUE(tenant_id, ...) would not
        # do this — Postgres treats every NULL as distinct in a unique
        # constraint, so without this partial index unlimited duplicate
        # global IOCs would be possible for the same indicator.
        Index(
            "uq_ioc_intelligence_iocs_global_identity",
            "ioc_type",
            "normalized_value",
            unique=True,
            postgresql_where=text("tenant_id IS NULL"),
        ),
        # Tenant identity: at most one row per (tenant_id, ioc_type,
        # normalized_value) when tenant_id IS NOT NULL — the same
        # canonical value may exist once per distinct tenant, and once
        # more globally, without colliding with either.
        Index(
            "uq_ioc_intelligence_iocs_tenant_identity",
            "tenant_id",
            "ioc_type",
            "normalized_value",
            unique=True,
            postgresql_where=text("tenant_id IS NOT NULL"),
        ),
    )


class IocSourceAttributionModel(Base):
    __tablename__ = "ioc_intelligence_source_attributions"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    ioc_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("ioc_intelligence_iocs.id", ondelete="CASCADE"),
        nullable=False,
    )
    source_system: Mapped[str] = mapped_column(String(64), nullable=False)
    external_id: Mapped[str] = mapped_column(String(512), nullable=False)
    content_hash: Mapped[str | None] = mapped_column(String(256), nullable=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    weight_applied: Mapped[float] = mapped_column(Float, nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    attribution_metadata: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False, default=dict)

    ioc: Mapped[IocModel] = relationship(back_populates="source_attributions")

    __table_args__ = (
        Index("ix_ioc_intelligence_source_attributions_ioc", "ioc_id"),
        Index(
            "uq_ioc_intelligence_source_attributions_dedup",
            "ioc_id",
            "source_system",
            "external_id",
            unique=True,
        ),
    )


class IocEvidenceCitationModel(Base):
    __tablename__ = "ioc_intelligence_evidence_citations"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    ioc_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("ioc_intelligence_iocs.id", ondelete="CASCADE"),
        nullable=False,
    )
    citation: Mapped[str] = mapped_column(String(2048), nullable=False)

    ioc: Mapped[IocModel] = relationship(back_populates="evidence_citations")

    __table_args__ = (
        Index("ix_ioc_intelligence_evidence_citations_ioc", "ioc_id"),
        Index(
            "uq_ioc_intelligence_evidence_citations_dedup",
            "ioc_id",
            "citation",
            unique=True,
        ),
    )
