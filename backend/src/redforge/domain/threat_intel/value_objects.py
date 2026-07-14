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


@unique
class IndicatorType(StrEnum):
    """Closed set of indicator kinds RedForge ever queries externally.

    File hashes are included for schema completeness but are only ever
    populated if RedForge itself genuinely observes one — never invented.
    """

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"


@unique
class ProviderName(StrEnum):
    """Closed set of external/local intelligence sources. Adding a new
    provider means adding a value here plus an adapter — never a free-text
    provider name, so evidence rows always trace to one verified source."""

    ABUSEIPDB = "abuseipdb"
    ALIENVAULT_OTX = "alienvault_otx"
    SPAMHAUS_DROP = "spamhaus_drop"
    RDAP = "rdap"
    MAXMIND_GEOLITE_LOCAL = "maxmind_geolite_local"
    IPINFO_LITE = "ipinfo_lite"
    # Optional adapters — ship disabled by default; see
    # docs/M18_INTELLIGENCE_PROVIDER_DECISION_MATRIX.md for the exact
    # licensing/quota reasoning behind the disabled default.
    GREYNOISE_COMMUNITY = "greynoise_community"
    ABUSECH = "abusech"


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
