from __future__ import annotations

from datetime import UTC, datetime

from threat_actor_intel.domain.factories.threat_actor_factory import ThreatActorFactory
from threat_actor_intel.domain.value_objects.enums import (
    ActivityStatus,
    MotivationType,
    SophisticationLevel,
    ThreatActorOrigin,
)
from threat_actor_intel.domain.value_objects.identifiers import TenantId
from threat_actor_intel.domain.value_objects.identity import ThreatActorName


def test_register_with_defaults() -> None:
    tenant_id = TenantId.generate()
    actor = ThreatActorFactory.register(
        tenant_id=tenant_id, name=ThreatActorName("APT29"), now=datetime.now(UTC)
    )
    assert actor.tenant_id == tenant_id
    assert actor.origin == ThreatActorOrigin.UNKNOWN
    assert actor.motivations == frozenset({MotivationType.UNKNOWN})
    assert actor.sophistication == SophisticationLevel.NOVICE
    assert actor.status == ActivityStatus.ACTIVE


def test_register_with_explicit_fields() -> None:
    tenant_id = TenantId.generate()
    actor = ThreatActorFactory.register(
        tenant_id=tenant_id,
        name=ThreatActorName("APT29"),
        now=datetime.now(UTC),
        origin=ThreatActorOrigin.NATION_STATE,
        motivations=frozenset({MotivationType.ESPIONAGE}),
        sophistication=SophisticationLevel.EXPERT,
    )
    assert actor.origin == ThreatActorOrigin.NATION_STATE
    assert actor.motivations == frozenset({MotivationType.ESPIONAGE})
    assert actor.sophistication == SophisticationLevel.EXPERT
