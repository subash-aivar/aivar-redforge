"""Predicate specifications for `ThreatActorAssociation` (M51.1),
consistent with `threat_actor_specifications`'s precedent (usable by
a future repository query layer, per Phase 3)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from threat_actor_intel.domain.aggregates.threat_actor_association import (
        ThreatActorAssociation,
    )


@dataclass(frozen=True, slots=True)
class IsActiveAssociationSpecification:
    def is_satisfied_by(self, association: ThreatActorAssociation) -> bool:
        return association.is_active()
