"""SQLAlchemy ORM models for the Threat Intelligence Reference Data
sub-context — M22 Phase 1 (ATT&CK Framework + CVE/KEV Foundation).

Five tables, all created in migration `0035`:

  - `attack_tactics` — GLOBAL, no `organization_id`. Canonical MITRE
    ATT&CK tactics (e.g. TA0001 "Initial Access").
  - `attack_techniques` — GLOBAL, no `organization_id`. Canonical MITRE
    ATT&CK techniques/sub-techniques.
  - `attack_technique_relationships` — GLOBAL, no `organization_id`.
    Raw STIX 2.1 relationship objects touching at least one technique.
  - `vulnerabilities` — GLOBAL, no `organization_id`. Canonical CVE
    records enriched with CVSS/EPSS/CISA-KEV overlay fields.
  - `stix_ingestion_log` — the idempotency gate for every write above.
    Carries a nullable `organization_id` (always NULL in Phase 1,
    reserved for Phase 2's per-tenant TAXII ingestion) and a `scope`
    discriminator so GLOBAL and TENANT idempotency keys never conflate
    — see the Hardening Review's Database Review (Part 3) for the
    defect this design closes.

Per the Hardening Review's P0 finding (Part 3, Database Review): global
reference tables must NEVER carry `organization_id` — doing so would
require one row per (tenant, technique) or (tenant, CVE), scaling
storage catastrophically. These four tables intentionally have no such
column, and no composite `(id, organization_id)` unique constraint
pattern used elsewhere in this codebase for tenant-scoped tables.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base


class AttackTacticModel(Base):
    """Canonical MITRE ATT&CK tactic. GLOBAL — no `organization_id`."""

    __tablename__ = "attack_tactics"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    tactic_id: Mapped[str] = mapped_column(String(20), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    shortname: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    stix_id: Mapped[str] = mapped_column(String(80), nullable=False)
    url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AttackTechniqueModel(Base):
    """Canonical MITRE ATT&CK technique or sub-technique. GLOBAL — no
    `organization_id`."""

    __tablename__ = "attack_techniques"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False)
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    stix_id: Mapped[str] = mapped_column(String(80), nullable=False)
    is_sub_technique: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Self-referential FK on the natural key (technique_id carries its own
    # unique constraint — see migration 0035), not the surrogate id, so a
    # sub-technique can be upserted before or after its parent without
    # ordering constraints on id generation.
    parent_technique_id: Mapped[str | None] = mapped_column(
        String(20),
        ForeignKey(
            "attack_techniques.technique_id",
            name="fk_atk_parent_technique",
            deferrable=True,
            initially="DEFERRED",
        ),
        nullable=True,
    )
    tactic_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    platforms: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    data_sources: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    is_deprecated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    framework_version: Mapped[str | None] = mapped_column(String(20), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AttackTechniqueRelationshipModel(Base):
    """Raw STIX 2.1 relationship object touching at least one technique.
    GLOBAL — no `organization_id`."""

    __tablename__ = "attack_technique_relationships"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    stix_id: Mapped[str] = mapped_column(String(80), nullable=False)
    relationship_type: Mapped[str] = mapped_column(String(30), nullable=False)
    source_ref: Mapped[str] = mapped_column(String(120), nullable=False)
    target_ref: Mapped[str] = mapped_column(String(120), nullable=False)
    source_technique_id: Mapped[str | None] = mapped_column(
        String(20),
        ForeignKey(
            "attack_techniques.technique_id",
            name="fk_atr_source_technique",
            deferrable=True,
            initially="DEFERRED",
        ),
        nullable=True,
    )
    target_technique_id: Mapped[str | None] = mapped_column(
        String(20),
        ForeignKey(
            "attack_techniques.technique_id",
            name="fk_atr_target_technique",
            deferrable=True,
            initially="DEFERRED",
        ),
        nullable=True,
    )
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class VulnerabilityModel(Base):
    """Canonical CVE record with CVSS/EPSS/CISA-KEV overlay fields.
    GLOBAL — no `organization_id`."""

    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(30), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    cvss_v3_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_v3_vector: Mapped[str | None] = mapped_column(String(100), nullable=True)
    cvss_v3_version: Mapped[str | None] = mapped_column(String(10), nullable=True)
    cvss_v2_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_probability: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_model_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_kev: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    kev_date_added: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    kev_due_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    kev_vulnerability_name: Mapped[str | None] = mapped_column(String(300), nullable=True)
    kev_short_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    kev_required_action: Mapped[str | None] = mapped_column(Text, nullable=True)
    kev_known_ransomware_use: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_modified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    source_last_synced_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class StixIngestionLogModel(Base):
    """Idempotency gate for every global reference-data write (and, in a
    future phase, per-tenant STIX/TAXII ingestion). See migration 0035
    for the partial-unique-index pair that keeps GLOBAL and TENANT
    idempotency keys from conflating.
    """

    __tablename__ = "stix_ingestion_log"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    source_system: Mapped[str] = mapped_column(String(30), nullable=False)
    scope: Mapped[str] = mapped_column(String(10), nullable=False, default="GLOBAL")
    organization_id: Mapped[str | None] = mapped_column(String(26), nullable=True)
    object_type: Mapped[str] = mapped_column(String(30), nullable=False)
    external_id: Mapped[str] = mapped_column(String(120), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    batch_id: Mapped[str | None] = mapped_column(String(26), nullable=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
