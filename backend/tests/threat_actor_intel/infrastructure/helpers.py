"""Shared fixture builders for threat_actor_intel's infrastructure
integration tests, mirroring `tests/risk_engine/infrastructure/
helpers.py`'s convention."""

from __future__ import annotations

from datetime import UTC, datetime

from threat_actor_intel.domain.aggregates.threat_actor import ThreatActor
from threat_actor_intel.domain.aggregates.threat_actor_association import ThreatActorAssociation
from threat_actor_intel.domain.value_objects.enums import (
    MotivationType,
    SophisticationLevel,
    ThreatActorOrigin,
)
from threat_actor_intel.domain.value_objects.evidence import EvidenceCitation
from threat_actor_intel.domain.value_objects.identifiers import (
    TenantId,
    ThreatActorAssociationId,
    ThreatActorId,
)
from threat_actor_intel.domain.value_objects.identity import ThreatActorName
from threat_actor_intel.domain.value_objects.references import ReferencedEntityRef


def make_tenant_id() -> TenantId:
    return TenantId.generate()


def make_threat_actor(
    tenant_id: TenantId | None = None,
    name: str = "APT29",
    sophistication: SophisticationLevel = SophisticationLevel.EXPERT,
) -> ThreatActor:
    return ThreatActor.register(
        threat_actor_id=ThreatActorId.generate(),
        tenant_id=tenant_id,
        name=ThreatActorName(name),
        origin=ThreatActorOrigin.NATION_STATE,
        motivations=frozenset({MotivationType.ESPIONAGE}),
        sophistication=sophistication,
        now=datetime.now(UTC),
    )


def make_association(
    tenant_id: TenantId,
    threat_actor_id: ThreatActorId,
    entity_type: str = "SecurityCondition",
    entity_id: str = "cond-1",
    evidence_citation: str = "cond-1 evidence chain",
) -> ThreatActorAssociation:
    return ThreatActorAssociation.create(
        association_id=ThreatActorAssociationId.generate(),
        tenant_id=tenant_id,
        threat_actor_id=threat_actor_id,
        referenced_entity=ReferencedEntityRef(entity_type=entity_type, entity_id=entity_id),
        evidence_citation=EvidenceCitation(evidence_citation),
        now=datetime.now(UTC),
    )
