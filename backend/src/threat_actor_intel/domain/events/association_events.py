"""Domain events emitted by the `ThreatActorAssociation` aggregate
(M51.1)."""

from __future__ import annotations

from dataclasses import dataclass

from threat_actor_intel.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True)
class ThreatActorAssociationCreated(BaseDomainEvent):
    threat_actor_id: str = ""
    referenced_entity_type: str = ""
    referenced_entity_id: str = ""
    evidence_citation: str = ""


@dataclass(frozen=True, slots=True)
class ThreatActorAssociationRetracted(BaseDomainEvent):
    threat_actor_id: str = ""
    referenced_entity_type: str = ""
    referenced_entity_id: str = ""
