"""SQLAlchemy ORM models for the Threat Intelligence bounded context
(M18 expansion pass). Three tables only:

  - `threat_intel_providers` — admin-configured enable/disable + an
    allowlisted non-secret config blob + a credential REFERENCE (never
    a secret value), mirroring the exact pattern established by
    `IntegrationProviderModel` (M18 command_center.py).
  - `threat_intel_indicators` — the canonical (organization, indicator)
    identity RedForge has genuinely observed or queried, with
    first/last-seen timestamps. Never a fabricated indicator.
  - `threat_intel_enrichments` — one cached evidence row per
    (indicator, provider, kind). `data` holds ONLY the canonical,
    documented fields defined in `domain/threat_intel/results.py` —
    never an arbitrary raw provider JSON dump.
"""

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKeyConstraint,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base


class ThreatIntelProviderModel(Base):
    """Per-organization admin configuration for one intelligence
    provider. Absence of a row (or `enabled=False`) means that provider
    is never called for that organization — this is the enforcement
    point for Priority 11's data-egress controls."""

    __tablename__ = "threat_intel_providers"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="ux_tip_id_org"),
        UniqueConstraint("organization_id", "provider_name", name="ux_tip_org_provider"),
        Index("ix_tip_org_provider", "organization_id", "provider_name"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    provider_name: Mapped[str] = mapped_column(String(40), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Allowed indicator types this provider may be queried with for this
    # org, e.g. ["ip"] — enforced before every call, never bypassed.
    allowed_indicator_types: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    # A REFERENCE only (e.g. an env var name like "ABUSEIPDB_API_KEY")
    # — never the credential value itself. Mirrors IntegrationProviderModel.
    credential_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    # Allowlisted, non-secret config (e.g. {"mmdb_path": "/etc/redforge/GeoLite2-City.mmdb"}).
    config: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    updated_by: Mapped[str] = mapped_column(String(26), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ThreatIntelIndicatorModel(Base):
    """Canonical (organization, indicator_type, indicator) identity.
    Created only when RedForge genuinely observes or queries this
    indicator — never pre-populated or invented."""

    __tablename__ = "threat_intel_indicators"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="ux_tii_id_org"),
        UniqueConstraint(
            "organization_id",
            "indicator_type",
            "indicator",
            name="ux_tii_org_type_indicator",
        ),
        Index("ix_tii_org_last_seen", "organization_id", "last_seen_at"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    indicator: Mapped[str] = mapped_column(String(512), nullable=False)
    indicator_type: Mapped[str] = mapped_column(String(20), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ThreatIntelEnrichmentModel(Base):
    """One cached evidence row per (indicator, provider, kind). Acts as
    both the TTL cache AND the minimal provider-health signal (a
    `success=False` row records `error_category` without ever storing
    a raw provider response body or secret)."""

    __tablename__ = "threat_intel_enrichments"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="ux_tie_id_org"),
        UniqueConstraint(
            "organization_id",
            "indicator_id",
            "provider_name",
            "kind",
            name="ux_tie_org_indicator_provider_kind",
        ),
        ForeignKeyConstraint(
            ["indicator_id", "organization_id"],
            ["threat_intel_indicators.id", "threat_intel_indicators.organization_id"],
            name="fk_tie_same_tenant_indicator",
            ondelete="CASCADE",
        ),
        Index("ix_tie_org_provider_fetched", "organization_id", "provider_name", "fetched_at"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    indicator_id: Mapped[str] = mapped_column(String(26), nullable=False)
    provider_name: Mapped[str] = mapped_column(String(40), nullable=False)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    error_category: Mapped[str | None] = mapped_column(String(40), nullable=True)
    # Canonical, documented fields only (one fixed schema per `kind`,
    # matching the dataclasses in domain/threat_intel/results.py).
    data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
