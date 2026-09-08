"""Domain events emitted by the `ThreatActor` aggregate (M51A)."""

from __future__ import annotations

from dataclasses import dataclass, field

from threat_actor_intel.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True)
class ThreatActorRegistered(BaseDomainEvent):
    name: str = ""
    origin: str = ""


@dataclass(frozen=True, slots=True)
class ThreatActorAliasAdded(BaseDomainEvent):
    alias: str = ""


@dataclass(frozen=True, slots=True)
class ThreatActorTechniqueAssociated(BaseDomainEvent):
    technique_id: str = ""


@dataclass(frozen=True, slots=True)
class ThreatActorIndicatorAssociated(BaseDomainEvent):
    indicator_id: str = ""


@dataclass(frozen=True, slots=True)
class ThreatActorMotivationUpdated(BaseDomainEvent):
    motivations: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class ThreatActorSophisticationUpdated(BaseDomainEvent):
    sophistication: str = ""


@dataclass(frozen=True, slots=True)
class ThreatActorAttributionConfidenceChanged(BaseDomainEvent):
    confidence: str = ""


@dataclass(frozen=True, slots=True)
class ThreatActorActivityStatusChanged(BaseDomainEvent):
    from_status: str = ""
    to_status: str = ""
