"""Closed enums for infrastructure_intel.

`InfrastructureLifecycleStatus` is RedForge's OWN record lifecycle (is
this intelligence RECORD still the one to trust?) — it says nothing
about whether the adversary infrastructure is still reachable or still
in use in the wild.

`CloudProvider` deliberately duplicates the *idea* of
`cloud_security`'s provider enum but is DEFINED LOCALLY: that context
enumerates providers RedForge's own cloud accounts are registered
with, an unrelated concept, and sharing an enum across bounded contexts
silently couples their independent evolution.
"""

from __future__ import annotations

from enum import StrEnum, unique

__all__ = [
    "CloudProvider",
    "InfrastructureConfidence",
    "InfrastructureLifecycleStatus",
    "InfrastructureType",
]


@unique
class InfrastructureLifecycleStatus(StrEnum):
    """RedForge-native RECORD lifecycle for an `Infrastructure` intel
    record. See `LifecycleTransitionPolicy` for the enforced transition
    table."""

    ACTIVE = "active"
    DEPRECATED = "deprecated"
    REVOKED = "revoked"
    SUPERSEDED = "superseded"


@unique
class InfrastructureType(StrEnum):
    """What KIND of hosting/ownership footprint this record describes.

    Note the deliberate overlap in vocabulary with `ioc_intelligence`'s
    `IndicatorType` (IP/DOMAIN/URL): there, those name atomic INDICATOR
    OBSERVATIONS with their own evidence-first epistemic lifecycle;
    here, they name the hosting ENTITY considered as adversary
    infrastructure. The two are linked externally through
    `intelligence_relationships`' `IOC_TO_INFRASTRUCTURE` type, never
    merged."""

    ASN = "asn"
    HOSTING_PROVIDER = "hosting_provider"
    CLOUD_PROVIDER = "cloud_provider"
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    URL = "url"


@unique
class CloudProvider(StrEnum):
    """Cloud tenancy an infrastructure footprint sits in. Defined
    locally on purpose — never imported from `cloud_security`, which
    models RedForge's own cloud account registrations."""

    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    ALIBABA_CLOUD = "alibaba_cloud"
    DIGITALOCEAN = "digitalocean"
    OVH = "ovh"
    OTHER = "other"


@unique
class InfrastructureConfidence(StrEnum):
    """Analyst confidence in a claim about this infrastructure."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"
