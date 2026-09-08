"""Simple predicate specifications for threat_actor_intel (M51A).

Implemented as lightweight frozen dataclasses with an
`is_satisfied_by(...)` method, consistent with `attack_surface_
management.domain.specifications.asset_specifications`'s precedent
(usable by a future repository query layer, per M51B)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from threat_actor_intel.domain.value_objects.enums import ActivityStatus, AttributionConfidence

if TYPE_CHECKING:
    from threat_actor_intel.domain.aggregates.threat_actor import ThreatActor


@dataclass(frozen=True, slots=True)
class IsActiveThreatActorSpecification:
    def is_satisfied_by(self, actor: ThreatActor) -> bool:
        return actor.status == ActivityStatus.ACTIVE


@dataclass(frozen=True, slots=True)
class HasHighAttributionConfidenceSpecification:
    def is_satisfied_by(self, actor: ThreatActor) -> bool:
        return actor.attribution_confidence == AttributionConfidence.HIGH


@dataclass(frozen=True, slots=True)
class IsAssociatedWithTechniqueSpecification:
    technique_id: str

    def is_satisfied_by(self, actor: ThreatActor) -> bool:
        return any(ref.technique_id == self.technique_id for ref in actor.technique_refs)


@dataclass(frozen=True, slots=True)
class IsAssociatedWithIndicatorSpecification:
    indicator_id: str

    def is_satisfied_by(self, actor: ThreatActor) -> bool:
        return any(ref.indicator_id == self.indicator_id for ref in actor.indicator_refs)


@dataclass(frozen=True, slots=True)
class HasAliasSpecification:
    alias: str

    def is_satisfied_by(self, actor: ThreatActor) -> bool:
        normalized = self.alias.strip().casefold()
        return any(a.normalized() == normalized for a in actor.aliases)
