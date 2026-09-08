"""Domain events emitted by the `Infrastructure` aggregate."""

from __future__ import annotations

from dataclasses import dataclass

from infrastructure_intel.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True)
class InfrastructureObserved(BaseDomainEvent):
    infrastructure_type: str = ""
    normalized_identifier: str = ""
    confidence: str = ""


@dataclass(frozen=True, slots=True)
class HostingProviderSet(BaseDomainEvent):
    provider_name: str = ""


@dataclass(frozen=True, slots=True)
class CloudProviderSet(BaseDomainEvent):
    provider: str = ""


@dataclass(frozen=True, slots=True)
class RegionAdded(BaseDomainEvent):
    region_code: str = ""


@dataclass(frozen=True, slots=True)
class NetworkOwnershipSet(BaseDomainEvent):
    registrant_organization: str = ""


@dataclass(frozen=True, slots=True)
class EvidenceCitationAdded(BaseDomainEvent):
    citation: str = ""


@dataclass(frozen=True, slots=True)
class SourceAttributionAdded(BaseDomainEvent):
    source_system: str = ""
    confidence: str = ""


@dataclass(frozen=True, slots=True)
class InfrastructureDeprecated(BaseDomainEvent):
    pass


@dataclass(frozen=True, slots=True)
class InfrastructureRevoked(BaseDomainEvent):
    pass


@dataclass(frozen=True, slots=True)
class InfrastructureSuperseded(BaseDomainEvent):
    superseded_by: str = ""


@dataclass(frozen=True, slots=True)
class InfrastructureReactivated(BaseDomainEvent):
    pass
