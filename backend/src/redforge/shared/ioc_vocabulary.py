"""Neutral, shared closed vocabularies for indicator-of-compromise
concepts used by more than one bounded context (`ioc_intelligence` and
`redforge.domain.threat_intel`). Living in `redforge.shared` — the
same shared-kernel location as `EntityId` (ADR-0005) — so neither
context depends on the other's private domain module. Introduced by
the M51.2 Phase A.1 ownership-reconciliation audit (R1/R2): both
`IndicatorType` and `ProviderName` previously existed as duplicated or
unconstrained definitions in `ioc_intelligence` and
`redforge.domain.threat_intel.value_objects`.
"""

from __future__ import annotations

from enum import StrEnum, unique


@unique
class IndicatorType(StrEnum):
    """Closed set of observable indicator kinds. Exactly four values —
    IP/DOMAIN/URL/HASH — persisted and serialized verbatim; never
    renamed or extended without a deliberate, repository-audited
    decision in both consuming contexts."""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"


@unique
class ProviderName(StrEnum):
    """Closed set of external/local intelligence sources RedForge may
    query or attribute evidence to. Adding a new provider means adding
    a value here plus an adapter — never a free-text provider name, so
    every piece of attributed evidence traces to one verified source."""

    ABUSEIPDB = "abuseipdb"
    ALIENVAULT_OTX = "alienvault_otx"
    SPAMHAUS_DROP = "spamhaus_drop"
    RDAP = "rdap"
    MAXMIND_GEOLITE_LOCAL = "maxmind_geolite_local"
    IPINFO_LITE = "ipinfo_lite"
    GREYNOISE_COMMUNITY = "greynoise_community"
    ABUSECH = "abusech"


IOC_INTERNAL_SOURCE_SYSTEM = "redforge_internal_observation"
"""The one explicit internal-source variant (M51.2 Phase A.1 R1):
identifies evidence RedForge itself generated (tenant-observed,
analyst-asserted) rather than an external provider. Deliberately kept
OUT of `ProviderName` — that enum's closed set gates real external
egress decisions (`EgressDecision`, `allowed_indicator_types`), and
conflating "no external call was made" with "one of N governed
providers" would weaken that invariant. A plain sentinel string, not a
second enum, since it is exactly one value."""
