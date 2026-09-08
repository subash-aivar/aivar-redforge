"""LifecycleTransitionPolicy — the legal
`RelationshipLifecycleStatus` transition table (M51.4 Phase C1).

Mirrors `attack_pattern_intel`'s `LifecycleTransitionPolicy` table
exactly (replicated locally, never imported):

    ACTIVE     -> {DEPRECATED, REVOKED, SUPERSEDED}
    DEPRECATED -> {REVOKED, ACTIVE}   (ACTIVE = reactivate)
    SUPERSEDED -> {REVOKED}
    REVOKED    -> {}                  (terminal — no transitions out)

`SUPERSEDED` additionally requires a `superseded_by` id — enforced by
the aggregate, not this policy (this policy only knows about the
enum-state graph).
"""

from __future__ import annotations

from intelligence_relationships.domain.exceptions.domain_exceptions import (
    InvalidLifecycleTransitionError,
)
from intelligence_relationships.domain.value_objects.enums import RelationshipLifecycleStatus

_ALLOWED_TRANSITIONS: dict[RelationshipLifecycleStatus, frozenset[RelationshipLifecycleStatus]] = {
    RelationshipLifecycleStatus.ACTIVE: frozenset(
        {
            RelationshipLifecycleStatus.DEPRECATED,
            RelationshipLifecycleStatus.REVOKED,
            RelationshipLifecycleStatus.SUPERSEDED,
        }
    ),
    RelationshipLifecycleStatus.DEPRECATED: frozenset(
        {
            RelationshipLifecycleStatus.REVOKED,
            RelationshipLifecycleStatus.ACTIVE,
        }
    ),
    RelationshipLifecycleStatus.SUPERSEDED: frozenset({RelationshipLifecycleStatus.REVOKED}),
    RelationshipLifecycleStatus.REVOKED: frozenset(),
}


class LifecycleTransitionPolicy:
    @staticmethod
    def assert_legal_transition(
        current: RelationshipLifecycleStatus, target: RelationshipLifecycleStatus
    ) -> None:
        if target not in _ALLOWED_TRANSITIONS[current]:
            raise InvalidLifecycleTransitionError(current.value, target.value)

    @staticmethod
    def allowed_targets(
        current: RelationshipLifecycleStatus,
    ) -> frozenset[RelationshipLifecycleStatus]:
        return _ALLOWED_TRANSITIONS[current]
