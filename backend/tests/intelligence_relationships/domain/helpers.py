"""Shared pure-domain builders for intelligence_relationships tests."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from intelligence_relationships.domain.aggregates.intelligence_relationship import (
    IntelligenceRelationship,
)
from intelligence_relationships.domain.value_objects.entity_ref import EntityRef
from intelligence_relationships.domain.value_objects.enums import (
    EntityType,
    EpistemicState,
    RelationshipConfidence,
    RelationshipDirection,
    RelationshipType,
)
from intelligence_relationships.domain.value_objects.evidence import SourceAttribution
from intelligence_relationships.domain.value_objects.identifiers import (
    IntelligenceRelationshipId,
    TenantId,
)
from intelligence_relationships.domain.value_objects.validity import Validity

NOW = datetime(2026, 8, 5, tzinfo=UTC)


def make_tenant_id() -> TenantId:
    return TenantId.generate()


def make_attribution(source_system: str = "redforge-analyst") -> SourceAttribution:
    return SourceAttribution(
        source_system=source_system,
        reference=f"ref-{uuid4()}",
        observed_at=NOW,
        confidence=RelationshipConfidence.HIGH,
    )


def malware_ref(entity_id: str | None = None) -> EntityRef:
    return EntityRef(EntityType.MALWARE, entity_id or f"malware-{uuid4()}")


def campaign_ref(entity_id: str | None = None) -> EntityRef:
    return EntityRef(EntityType.CAMPAIGN, entity_id or f"campaign-{uuid4()}")


def threat_report_ref(entity_id: str | None = None) -> EntityRef:
    return EntityRef(EntityType.THREAT_REPORT, entity_id or f"threat-report-{uuid4()}")


def threat_actor_ref(entity_id: str | None = None) -> EntityRef:
    return EntityRef(EntityType.THREAT_ACTOR, entity_id or f"threat-actor-{uuid4()}")


def tool_ref(entity_id: str | None = None) -> EntityRef:
    return EntityRef(EntityType.TOOL, entity_id or f"tool-{uuid4()}")


def infrastructure_ref(entity_id: str | None = None) -> EntityRef:
    return EntityRef(EntityType.INFRASTRUCTURE, entity_id or f"infrastructure-{uuid4()}")


def attack_pattern_ref(entity_id: str | None = None) -> EntityRef:
    return EntityRef(EntityType.ATTACK_PATTERN, entity_id or f"attack-pattern-{uuid4()}")


def ioc_ref(entity_id: str | None = None) -> EntityRef:
    return EntityRef(EntityType.IOC, entity_id or f"ioc-{uuid4()}")


def make_relationship(
    *,
    tenant_id: TenantId | None = None,
    relationship_type: RelationshipType = RelationshipType.MALWARE_TO_CAMPAIGN,
    source_entity: EntityRef | None = None,
    target_entity: EntityRef | None = None,
    direction: RelationshipDirection = RelationshipDirection.UNIDIRECTIONAL,
    confidence: RelationshipConfidence = RelationshipConfidence.MEDIUM,
    epistemic_state: EpistemicState = EpistemicState.OBSERVATION,
) -> IntelligenceRelationship:
    return IntelligenceRelationship.observe(
        relationship_id=IntelligenceRelationshipId.generate(),
        tenant_id=tenant_id,
        relationship_type=relationship_type,
        source_entity=source_entity or malware_ref(),
        target_entity=target_entity or campaign_ref(),
        direction=direction,
        confidence=confidence,
        validity=Validity(valid_from=NOW),
        now=NOW,
        epistemic_state=epistemic_state,
    )


def advance_epistemic_to(
    relationship: IntelligenceRelationship, target: EpistemicState
) -> IntelligenceRelationship:
    """Walk the legal epistemic path from OBSERVATION up to `target`."""
    path = [
        EpistemicState.EVIDENCE,
        EpistemicState.HYPOTHESIS,
        EpistemicState.CORROBORATED,
        EpistemicState.VALIDATED,
    ]
    for state in path:
        relationship.transition_epistemic_state(
            relationship.tenant_id, state, make_attribution(), NOW
        )
        if state is target:
            return relationship
    relationship.transition_epistemic_state(relationship.tenant_id, target, make_attribution(), NOW)
    return relationship
