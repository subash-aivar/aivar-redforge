"""RelationshipIdentityPolicy — no duplicate
(scope, relationship_type, source_entity, target_entity) within
`intelligence_relationships`.

The domain-layer half of the two-layer defense; see
`IntelligenceRelationshipApplicationService` for the
repository-existence-check half, mirroring `attack_pattern_intel`'s
and `ioc_intelligence`'s dedup discipline. Scope is not re-checked
here: the caller only ever passes candidates already loaded from a
single scope.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from intelligence_relationships.domain.exceptions.domain_exceptions import (
    DuplicateRelationshipError,
)

if TYPE_CHECKING:
    from intelligence_relationships.domain.aggregates.intelligence_relationship import (
        IntelligenceRelationship,
    )
    from intelligence_relationships.domain.value_objects.entity_ref import EntityRef
    from intelligence_relationships.domain.value_objects.enums import RelationshipType


def identity_key(
    relationship_type: RelationshipType,
    source_entity: EntityRef,
    target_entity: EntityRef,
) -> str:
    """The canonical identity string of a relationship within one
    scope. Direction is deliberately NOT part of identity: a
    bidirectional and a unidirectional claim over the same ordered
    endpoints are the same edge, differing only in what is asserted
    about it."""
    return f"{relationship_type.value}|{source_entity.key}|{target_entity.key}"


class RelationshipIdentityPolicy:
    @staticmethod
    def assert_no_duplicate(
        existing: list[IntelligenceRelationship],
        relationship_type: RelationshipType,
        source_entity: EntityRef,
        target_entity: EntityRef,
    ) -> None:
        candidate = identity_key(relationship_type, source_entity, target_entity)
        for relationship in existing:
            if relationship.identity_key == candidate:
                raise DuplicateRelationshipError(candidate)
