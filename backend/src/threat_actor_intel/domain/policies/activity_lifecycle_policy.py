"""ActivityLifecyclePolicy — the legal `ActivityStatus` transition
table for `ThreatActor` (M51A).

`ACTIVE ⇄ DORMANT`, both terminating in `DISBANDED`; `DISBANDED` is
terminal (no transition leaves it). Extracted into a standalone
policy — rather than inlined `if` checks on the aggregate — so the
transition table has one canonical location, matching
`attack_surface_management.domain.policies.
lifecycle_transition_policy`'s precedent.
"""

from __future__ import annotations

from threat_actor_intel.domain.exceptions.domain_exceptions import (
    InvalidActivityStatusTransition,
)
from threat_actor_intel.domain.value_objects.enums import ActivityStatus

_LEGAL_TRANSITIONS: dict[ActivityStatus, frozenset[ActivityStatus]] = {
    ActivityStatus.ACTIVE: frozenset({ActivityStatus.DORMANT, ActivityStatus.DISBANDED}),
    ActivityStatus.DORMANT: frozenset({ActivityStatus.ACTIVE, ActivityStatus.DISBANDED}),
    ActivityStatus.DISBANDED: frozenset(),
}


class ActivityLifecyclePolicy:
    @staticmethod
    def assert_legal_transition(current: ActivityStatus, target: ActivityStatus) -> None:
        if target not in _LEGAL_TRANSITIONS[current]:
            raise InvalidActivityStatusTransition(current.value, target.value)
