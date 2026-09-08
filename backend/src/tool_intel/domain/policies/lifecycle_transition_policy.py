"""LifecycleTransitionPolicy — the legal `ToolLifecycleStatus`
transition table.

This governs RedForge's OWN RECORD lifecycle only — it says nothing
about whether the adversary tool is still used in the wild.

Transition table (identical to `campaign_intel`'s and `malware_intel`'s
`LifecycleTransitionPolicy`, enforced here — the single source of truth,
not merely a docstring elsewhere):

    ACTIVE     -> {DEPRECATED, REVOKED, SUPERSEDED}
    DEPRECATED -> {REVOKED, ACTIVE}   (ACTIVE = reactivate)
    SUPERSEDED -> {REVOKED}
    REVOKED    -> {}                  (terminal — no transitions out)

`SUPERSEDED` additionally requires a `superseded_by` id — enforced by
the aggregate, not this policy (this policy only knows about the
enum-state graph).
"""

from __future__ import annotations

from tool_intel.domain.exceptions.domain_exceptions import (
    InvalidLifecycleTransitionError,
)
from tool_intel.domain.value_objects.enums import ToolLifecycleStatus

_ALLOWED_TRANSITIONS: dict[ToolLifecycleStatus, frozenset[ToolLifecycleStatus]] = {
    ToolLifecycleStatus.ACTIVE: frozenset(
        {
            ToolLifecycleStatus.DEPRECATED,
            ToolLifecycleStatus.REVOKED,
            ToolLifecycleStatus.SUPERSEDED,
        }
    ),
    ToolLifecycleStatus.DEPRECATED: frozenset(
        {
            ToolLifecycleStatus.REVOKED,
            ToolLifecycleStatus.ACTIVE,
        }
    ),
    ToolLifecycleStatus.SUPERSEDED: frozenset({ToolLifecycleStatus.REVOKED}),
    ToolLifecycleStatus.REVOKED: frozenset(),
}


class LifecycleTransitionPolicy:
    @staticmethod
    def assert_legal_transition(current: ToolLifecycleStatus, target: ToolLifecycleStatus) -> None:
        if target not in _ALLOWED_TRANSITIONS[current]:
            raise InvalidLifecycleTransitionError(current.value, target.value)
