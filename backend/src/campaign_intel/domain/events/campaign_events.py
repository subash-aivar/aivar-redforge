"""Domain events emitted by the `Campaign` aggregate."""

from __future__ import annotations

from dataclasses import dataclass

from campaign_intel.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True)
class CampaignObserved(BaseDomainEvent):
    canonical_name: str = ""
    motivation: str = ""
    status: str = ""


@dataclass(frozen=True, slots=True)
class AliasAdded(BaseDomainEvent):
    alias: str = ""


@dataclass(frozen=True, slots=True)
class ObjectiveAdded(BaseDomainEvent):
    objective_type: str = ""
    description: str = ""


@dataclass(frozen=True, slots=True)
class RegionAdded(BaseDomainEvent):
    region: str = ""


@dataclass(frozen=True, slots=True)
class TargetSectorAdded(BaseDomainEvent):
    target_sector: str = ""


@dataclass(frozen=True, slots=True)
class StatusTransitioned(BaseDomainEvent):
    """The REAL-WORLD campaign's own operational status changed — never
    the RedForge record lifecycle (see `CampaignDeprecated` et al.)."""

    from_status: str = ""
    to_status: str = ""


@dataclass(frozen=True, slots=True)
class EvidenceCitationAdded(BaseDomainEvent):
    citation: str = ""


@dataclass(frozen=True, slots=True)
class SourceAttributionAdded(BaseDomainEvent):
    source_system: str = ""
    confidence: str = ""


@dataclass(frozen=True, slots=True)
class CampaignDeprecated(BaseDomainEvent):
    pass


@dataclass(frozen=True, slots=True)
class CampaignRevoked(BaseDomainEvent):
    pass


@dataclass(frozen=True, slots=True)
class CampaignSuperseded(BaseDomainEvent):
    superseded_by: str = ""


@dataclass(frozen=True, slots=True)
class CampaignReactivated(BaseDomainEvent):
    pass
