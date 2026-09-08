"""IntelligenceRelationshipFactory — the single supported construction
path for `IntelligenceRelationship` aggregates (M51.4 Phase C1).

Stays pure/sync: it does NOT call any ACL port itself. Existence of
the RedForge-native endpoints (IOC / threat actor / attack pattern)
must already have been validated by the application service BEFORE
this factory is invoked — mirroring `attack_pattern_intel`'s exact
factory-stays-pure discipline.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from intelligence_relationships.domain.aggregates.intelligence_relationship import (
    IntelligenceRelationship,
)
from intelligence_relationships.domain.value_objects.enums import EpistemicState
from intelligence_relationships.domain.value_objects.identifiers import (
    IntelligenceRelationshipId,
)

if TYPE_CHECKING:
    from datetime import datetime

    from intelligence_relationships.domain.value_objects.entity_ref import EntityRef
    from intelligence_relationships.domain.value_objects.enums import (
        RelationshipConfidence,
        RelationshipDirection,
        RelationshipType,
    )
    from intelligence_relationships.domain.value_objects.evidence import (
        EvidenceCitation,
        SourceAttribution,
    )
    from intelligence_relationships.domain.value_objects.identifiers import TenantId
    from intelligence_relationships.domain.value_objects.validity import Validity


class IntelligenceRelationshipFactory:
    def observe(
        self,
        tenant_id: TenantId | None,
        relationship_type: RelationshipType,
        source_entity: EntityRef,
        target_entity: EntityRef,
        direction: RelationshipDirection,
        confidence: RelationshipConfidence,
        validity: Validity,
        now: datetime,
        epistemic_state: EpistemicState = EpistemicState.OBSERVATION,
        evidence_citations: tuple[EvidenceCitation, ...] = (),
        source_attributions: tuple[SourceAttribution, ...] = (),
    ) -> IntelligenceRelationship:
        return IntelligenceRelationship.observe(
            relationship_id=IntelligenceRelationshipId.generate(),
            tenant_id=tenant_id,
            relationship_type=relationship_type,
            source_entity=source_entity,
            target_entity=target_entity,
            direction=direction,
            confidence=confidence,
            validity=validity,
            now=now,
            epistemic_state=epistemic_state,
            evidence_citations=evidence_citations,
            source_attributions=source_attributions,
        )
