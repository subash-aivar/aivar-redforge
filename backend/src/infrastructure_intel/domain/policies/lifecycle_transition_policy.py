"""LifecycleTransitionPolicy — the legal
`InfrastructureLifecycleStatus` transition table.

This governs RedForge's OWN RECORD lifecycle only — it says nothing
about whether the adversary infrastructure is still reachable or still
in use.

Transition table (identical to `campaign_intel`'s, `malware_intel`'s
and `tool_intel`'s `LifecycleTransitionPolicy`, enforced here — the
single source of truth, not merely a docstring elsewhere):

    ACTIVE     -> {DEPRECATED, REVOKED, SUPERSEDED}
    DEPRECATED -> {REVOKED, ACTIVE}   (ACTIVE = reactivate)
    SUPERSEDED -> {REVOKED}
    REVOKED    -> {}                  (terminal — no transitions out)

`SUPERSEDED` additionally requires a `superseded_by` id — enforced by
the aggregate, not this policy (this policy only knows about the
enum-state graph).
"""

from __future__ import annotations

from infrastructure_intel.domain.exceptions.domain_exceptions import (
    InvalidLifecycleTransitionError,
)
from infrastructure_intel.domain.value_objects.enums import InfrastructureLifecycleStatus

_ALLOWED_TRANSITIONS: dict[
    InfrastructureLifecycleStatus, frozenset[InfrastructureLifecycleStatus]
] = {
    InfrastructureLifecycleStatus.ACTIVE: frozenset(
        {
            InfrastructureLifecycleStatus.DEPRECATED,
            InfrastructureLifecycleStatus.REVOKED,
            InfrastructureLifecycleStatus.SUPERSEDED,
        }
    ),
    InfrastructureLifecycleStatus.DEPRECATED: frozenset(
        {
            InfrastructureLifecycleStatus.REVOKED,
            InfrastructureLifecycleStatus.ACTIVE,
        }
    ),
    InfrastructureLifecycleStatus.SUPERSEDED: frozenset({InfrastructureLifecycleStatus.REVOKED}),
    InfrastructureLifecycleStatus.REVOKED: frozenset(),
}


class LifecycleTransitionPolicy:
    @staticmethod
    def assert_legal_transition(
        current: InfrastructureLifecycleStatus, target: InfrastructureLifecycleStatus
    ) -> None:
        if target not in _ALLOWED_TRANSITIONS[current]:
            raise InvalidLifecycleTransitionError(current.value, target.value)
