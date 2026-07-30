"""Closed enums for the attack_surface_management bounded context
(M49A). Vocabulary only — attack surface facts (asset type, exposure,
lifecycle, criticality) are modeled here; no scanning/scoring logic
from any other bounded context is duplicated."""

from __future__ import annotations

from enum import StrEnum


class AssetType(StrEnum):
    """Where an asset sits relative to the organization's network
    perimeter. Distinct from `ExposureState`, which is the *observed*
    reachability of the asset — `AssetType` is the declared/intended
    placement, `ExposureState` is derived from actual discovery data."""

    EXTERNAL = "external"
    """Owned/managed by the organization but hosted outside its
    perimeter (e.g. a SaaS-hosted subdomain)."""

    INTERNAL = "internal"
    """Only reachable from within the organization's private network."""

    INTERNET_FACING = "internet_facing"
    """Explicitly intended to be reachable from the public internet."""


class ExposureState(StrEnum):
    """The *observed* reachability/risk posture of an asset, derived by
    `ExposureClassificationPolicy` from its `AssetType` and discovered
    ports — never set directly by a caller."""

    UNKNOWN = "unknown"
    NOT_EXPOSED = "not_exposed"
    INTERNET_FACING = "internet_facing"
    EXPOSED_HIGH_RISK = "exposed_high_risk"
    """Internet-facing with at least one high-risk open port/service
    (e.g. telnet, RDP, SMB, unauthenticated admin console)."""


class AssetClassification(StrEnum):
    """The business/environment tag an asset was discovered or
    confirmed to belong to."""

    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TEST = "test"
    UNKNOWN = "unknown"


class Criticality(StrEnum):
    """The business-assigned criticality tier of an asset, independent
    of its observed exposure — combined with `ExposureState` by
    `CriticalityScoringPolicy` to produce a numeric priority score."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNRATED = "unrated"


class AssetLifecycleState(StrEnum):
    """`DISCOVERED -> VALIDATED -> ACTIVE -> DECOMMISSIONED`, with
    `IGNORED` reachable from `DISCOVERED`/`VALIDATED` as a terminal
    false-positive/out-of-scope outcome. `DECOMMISSIONED` and `IGNORED`
    are both terminal."""

    DISCOVERED = "discovered"
    VALIDATED = "validated"
    ACTIVE = "active"
    DECOMMISSIONED = "decommissioned"
    IGNORED = "ignored"


class NetworkRangeLifecycleState(StrEnum):
    """`DISCOVERED -> ACTIVE -> RETIRED`, terminal at `RETIRED`."""

    DISCOVERED = "discovered"
    ACTIVE = "active"
    RETIRED = "retired"


class DiscoverySource(StrEnum):
    """How an asset/network-range was first observed. A small,
    deliberately generic vocabulary — this context never models the
    internal taxonomy of a scanning tool/integration, only the category
    of source that reported the observation."""

    PASSIVE_DNS = "passive_dns"
    CERTIFICATE_TRANSPARENCY = "certificate_transparency"
    ACTIVE_SCAN = "active_scan"
    CLOUD_PROVIDER_API = "cloud_provider_api"
    MANUAL_ENTRY = "manual_entry"
    THIRD_PARTY_FEED = "third_party_feed"
    WHOIS = "whois"


class DnsRecordType(StrEnum):
    A = "a"
    AAAA = "aaaa"
    CNAME = "cname"
    MX = "mx"
    TXT = "txt"
    NS = "ns"
    SOA = "soa"
    PTR = "ptr"
    SRV = "srv"
    CAA = "caa"


class PortProtocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"


class PortState(StrEnum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class CertificateStatus(StrEnum):
    VALID = "valid"
    EXPIRED = "expired"
    REVOKED = "revoked"
    SELF_SIGNED = "self_signed"
