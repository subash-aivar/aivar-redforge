"""LifecycleTransitionPolicy — the legal `TechniqueLifecycleStatus`
transition table (M51.3 Phase B1).

Transition table (documented per spec, enforced here — the single
source of truth, not merely a docstring elsewhere):

    ACTIVE     -> {DEPRECATED, REVOKED, SUPERSEDED}
    DEPRECATED -> {REVOKED, ACTIVE}   (ACTIVE = reactivate)
    SUPERSEDED -> {REVOKED}
    REVOKED    -> {}                  (terminal — no transitions out)

`SUPERSEDED` additionally requires a `superseded_by` id — enforced by
the aggregate, not this policy (this policy only knows about the
enum-state graph).
"""

from __future__ import annotations

from attack_pattern_intel.domain.exceptions.domain_exceptions import (
    InvalidLifecycleTransitionError,
)
from attack_pattern_intel.domain.value_objects.enums import TechniqueLifecycleStatus

_ALLOWED_TRANSITIONS: dict[TechniqueLifecycleStatus, frozenset[TechniqueLifecycleStatus]] = {
    TechniqueLifecycleStatus.ACTIVE: frozenset(
        {
            TechniqueLifecycleStatus.DEPRECATED,
            TechniqueLifecycleStatus.REVOKED,
            TechniqueLifecycleStatus.SUPERSEDED,
        }
    ),
    TechniqueLifecycleStatus.DEPRECATED: frozenset(
        {
            TechniqueLifecycleStatus.REVOKED,
            TechniqueLifecycleStatus.ACTIVE,
        }
    ),
    TechniqueLifecycleStatus.SUPERSEDED: frozenset({TechniqueLifecycleStatus.REVOKED}),
    TechniqueLifecycleStatus.REVOKED: frozenset(),
}


class LifecycleTransitionPolicy:
    @staticmethod
    def assert_legal_transition(
        current: TechniqueLifecycleStatus, target: TechniqueLifecycleStatus
    ) -> None:
        if target not in _ALLOWED_TRANSITIONS[current]:
            raise InvalidLifecycleTransitionError(current.value, target.value)
