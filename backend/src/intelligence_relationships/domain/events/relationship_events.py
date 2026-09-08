"""Domain events emitted by the `IntelligenceRelationship` aggregate
(M51.4 Phase C1). Every mutator emits exactly one."""

from __future__ import annotations

from dataclasses import dataclass

from intelligence_relationships.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True)
class IntelligenceRelationshipObserved(BaseDomainEvent):
    relationship_type: str = ""
    source_entity: str = ""
    target_entity: str = ""
    direction: str = ""
    confidence: str = ""
    epistemic_state: str = ""


@dataclass(frozen=True, slots=True)
class EvidenceCitationAdded(BaseDomainEvent):
    citation: str = ""


@dataclass(frozen=True, slots=True)
class SourceAttributionAdded(BaseDomainEvent):
    source_system: str = ""
    confidence: str = ""


@dataclass(frozen=True, slots=True)
class EpistemicStateTransitioned(BaseDomainEvent):
    from_state: str = ""
    to_state: str = ""


@dataclass(frozen=True, slots=True)
class IntelligenceRelationshipDeprecated(BaseDomainEvent):
    pass


@dataclass(frozen=True, slots=True)
class IntelligenceRelationshipRevoked(BaseDomainEvent):
    pass


@dataclass(frozen=True, slots=True)
class IntelligenceRelationshipSuperseded(BaseDomainEvent):
    superseded_by: str = ""


@dataclass(frozen=True, slots=True)
class IntelligenceRelationshipReactivated(BaseDomainEvent):
    pass
