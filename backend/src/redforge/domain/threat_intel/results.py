"""Canonical, provider-neutral result shapes for the Threat Intelligence
bounded context.

Every provider adapter returns one of these — never a raw provider JSON
dump passed through to the domain. Fields are only ever populated with
what that specific provider actually returned; nothing is inferred or
defaulted to a fabricated value. Confidence/scores keep the provider's
own semantics (documented in each field's docstring) rather than being
coerced into one fake universal "AI threat score".
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class ReputationEvidence:
    """One provider's reputation evidence for one indicator. `provider`
    identifies which source produced this — never merged across
    providers into a single verdict; aggregation (if any) happens as an
    explicit, documented sum in the application layer, never here."""

    provider: str
    indicator: str
    indicator_type: str
    # Confidence score AS DEFINED BY THE PROVIDER — e.g. AbuseIPDB's
    # abuseConfidenceScore is 0-100 "likelihood of abuse reports being
    # legitimate", not a universal probability. Never renormalized.
    confidence_score: float | None
    confidence_semantics: str
    categories: tuple[str, ...]
    report_count: int | None
    distinct_reporter_count: int | None
    last_reported_at: str | None
    provider_reference_id: str | None
    fetched_at: str
    raw_provider_url: str


@dataclass(frozen=True, slots=True)
class GeoEnrichment:
    """Approximate geolocation — enrichment, never proof of attack
    origin. City/lat-lon are only populated when the underlying source
    actually provides city-level resolution (e.g. a local MaxMind DB);
    a coarse country/ASN-only source leaves those fields None rather
    than guessing."""

    provider: str
    indicator: str
    country: str | None
    country_code: str | None
    region: str | None
    city: str | None
    latitude: float | None
    longitude: float | None
    asn: str | None
    organization: str | None
    timezone: str | None
    is_approximate: bool
    database_version_or_fetched_at: str
    fetched_at: str


@dataclass(frozen=True, slots=True)
class AsnEnrichment:
    provider: str
    indicator: str
    asn: str | None
    network_prefix: str | None
    organization: str | None
    country: str | None
    registration_date: str | None
    rir_source: str | None
    fetched_at: str


@dataclass(frozen=True, slots=True)
class IocMatch:
    """A real observed RedForge indicator that matched a configured
    threat-intelligence source. Never invented — the indicator must
    already exist in RedForge's own canonical data before this is
    produced."""

    provider: str
    indicator: str
    indicator_type: str
    threat_type: str | None
    malware_family: str | None
    tags: tuple[str, ...]
    provider_first_seen: str | None
    provider_last_seen: str | None
    provider_reference_id: str | None
    fetched_at: str


@dataclass(frozen=True, slots=True)
class ProviderCallOutcome:
    """Uniform success/failure envelope every adapter call resolves to,
    used to build provider health without leaking secrets or raw
    provider response bodies into logs/health state."""

    provider: str
    success: bool
    error_category: str | None = None  # e.g. "timeout", "auth_failure", "rate_limited"
    attempted_at: str = ""
    detail: str = field(default="")  # short, secret-free description only
