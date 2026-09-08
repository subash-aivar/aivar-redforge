"""Value objects for the Threat Intelligence bounded context (M18 expansion).

Distinct from `domain/intelligence` (the AI Security Intelligence &
Recommendation Engine, Sprint 21) — this bounded context is about external
IP/domain/IOC reputation, geolocation, RDAP, and IOC correlation evidence,
never about recommending fixes. No fabricated verdicts: reputation is
evidence, never a final classification; geolocation is approximate
enrichment, never proof of attack origin.
"""

from __future__ import annotations

from enum import StrEnum, unique

# IndicatorType and ProviderName are the neutral shared-kernel vocabularies
# (M51.2 Phase A.1 R1/R2) — re-exported here so every existing consumer of
# `redforge.domain.threat_intel.value_objects` keeps working unchanged and
# still receives the exact same type object `ioc_intelligence` uses.
from redforge.shared.ioc_vocabulary import IndicatorType, ProviderName

__all__ = [
    "EgressDecision",
    "EnrichmentKind",
    "IndicatorType",
    "ProviderHealthStatus",
    "ProviderName",
]


@unique
class EnrichmentKind(StrEnum):
    """Discriminates the shape of the canonical `data` JSON persisted per
    enrichment row — each kind has one fixed, documented schema (never an
    arbitrary provider dump)."""

    REPUTATION = "reputation"
    GEOLOCATION = "geolocation"
    ASN_RDAP = "asn_rdap"
    IOC_MATCH = "ioc_match"


@unique
class EgressDecision(StrEnum):
    """Why an indicator was or wasn't sent to an external provider —
    surfaced in the audit trail so "why didn't this enrich" is always
    answerable without reading logs."""

    ALLOWED = "allowed"
    BLOCKED_PRIVATE_ADDRESS = "blocked_private_address"
    BLOCKED_PROVIDER_DISABLED = "blocked_provider_disabled"
    BLOCKED_INDICATOR_TYPE_NOT_ALLOWED = "blocked_indicator_type_not_allowed"
    BLOCKED_NO_CREDENTIALS = "blocked_no_credentials"


@unique
class ProviderHealthStatus(StrEnum):
    NOT_CONFIGURED = "not_configured"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    RATE_LIMITED = "rate_limited"
    AUTH_FAILURE = "auth_failure"
    QUOTA_EXHAUSTED = "quota_exhausted"
    CIRCUIT_OPEN = "circuit_open"
