"""Predicate specifications over `IntelligenceRelationship` (M51.4
Phase C1). Pure, in-memory predicates only — no query building, no
persistence concerns (mirrors `attack_pattern_intel.domain.
specifications.attack_pattern_specifications`)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from intelligence_relationships.domain.policies.epistemic_transition_policy import (
    EpistemicTransitionPolicy,
)
from intelligence_relationships.domain.value_objects.enums import (
    EpistemicState,
    RelationshipLifecycleStatus,
)

if TYPE_CHECKING:
    from datetime import datetime

    from intelligence_relationships.domain.aggregates.intelligence_relationship import (
        IntelligenceRelationship,
    )
    from intelligence_relationships.domain.value_objects.enums import RelationshipType


class RelationshipSpecification(Protocol):
    def is_satisfied_by(self, relationship: IntelligenceRelationship) -> bool: ...


class IsGlobalRelationshipSpecification:
    def is_satisfied_by(self, relationship: IntelligenceRelationship) -> bool:
        return relationship.tenant_id is None


class IsTenantRelationshipSpecification:
    def is_satisfied_by(self, relationship: IntelligenceRelationship) -> bool:
        return relationship.tenant_id is not None


class ActiveRelationshipSpecification:
    def is_satisfied_by(self, relationship: IntelligenceRelationship) -> bool:
        return relationship.lifecycle_status is RelationshipLifecycleStatus.ACTIVE


class DeprecatedOrRevokedSpecification:
    _TERMINAL = frozenset(
        {RelationshipLifecycleStatus.DEPRECATED, RelationshipLifecycleStatus.REVOKED}
    )

    def is_satisfied_by(self, relationship: IntelligenceRelationship) -> bool:
        return relationship.lifecycle_status in self._TERMINAL


class SupersededRelationshipSpecification:
    def is_satisfied_by(self, relationship: IntelligenceRelationship) -> bool:
        return relationship.lifecycle_status is RelationshipLifecycleStatus.SUPERSEDED


class TrustedClaimSpecification:
    """Corroborated or validated — the epistemic states RedForge is
    willing to act on without further analyst review."""

    _TRUSTED = frozenset({EpistemicState.CORROBORATED, EpistemicState.VALIDATED})

    def is_satisfied_by(self, relationship: IntelligenceRelationship) -> bool:
        return relationship.epistemic_state in self._TRUSTED


class TerminalEpistemicStateSpecification:
    def is_satisfied_by(self, relationship: IntelligenceRelationship) -> bool:
        return EpistemicTransitionPolicy.is_terminal(relationship.epistemic_state)


class HasEvidenceSpecification:
    def is_satisfied_by(self, relationship: IntelligenceRelationship) -> bool:
        return bool(relationship.evidence_citations) or bool(relationship.source_attributions)


class RelationshipTypeSpecification:
    def __init__(self, relationship_type: RelationshipType) -> None:
        self._relationship_type = relationship_type

    def is_satisfied_by(self, relationship: IntelligenceRelationship) -> bool:
        return relationship.relationship_type is self._relationship_type


class ValidAtSpecification:
    def __init__(self, moment: datetime) -> None:
        self._moment = moment

    def is_satisfied_by(self, relationship: IntelligenceRelationship) -> bool:
        return relationship.validity.covers(self._moment)
