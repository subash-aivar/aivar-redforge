"""ThreatActorFactory — the recommended way to construct a
`ThreatActor`. Delegates entirely to `ThreatActor.register`, which
also enforces the same invariants directly (defense in depth,
matching `attack_surface_management`'s `AssetFactory`/`EnterpriseRiskProfile`'s
`RiskProfileFactory` split of "who is allowed to construct" vs "what
must be true to exist")."""

from __future__ import annotations

from typing import TYPE_CHECKING

from threat_actor_intel.domain.aggregates.threat_actor import ThreatActor
from threat_actor_intel.domain.value_objects.enums import (
    MotivationType,
    SophisticationLevel,
    ThreatActorOrigin,
)
from threat_actor_intel.domain.value_objects.identifiers import ThreatActorId

if TYPE_CHECKING:
    from datetime import datetime

    from threat_actor_intel.domain.value_objects.identifiers import TenantId
    from threat_actor_intel.domain.value_objects.identity import ThreatActorName


class ThreatActorFactory:
    @staticmethod
    def register(
        tenant_id: TenantId | None,
        name: ThreatActorName,
        now: datetime,
        origin: ThreatActorOrigin = ThreatActorOrigin.UNKNOWN,
        motivations: frozenset[MotivationType] | None = None,
        sophistication: SophisticationLevel = SophisticationLevel.NOVICE,
        threat_actor_id: ThreatActorId | None = None,
    ) -> ThreatActor:
        resolved_id = threat_actor_id or ThreatActorId.generate()
        resolved_motivations = motivations or frozenset({MotivationType.UNKNOWN})
        return ThreatActor.register(
            threat_actor_id=resolved_id,
            tenant_id=tenant_id,
            name=name,
            origin=origin,
            motivations=resolved_motivations,
            sophistication=sophistication,
            now=now,
        )
