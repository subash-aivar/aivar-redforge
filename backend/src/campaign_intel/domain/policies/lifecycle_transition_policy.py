"""LifecycleTransitionPolicy — the legal `CampaignLifecycleStatus`
transition table.

This governs RedForge's OWN RECORD lifecycle only. The real-world
campaign's operational state has its own, completely independent table
in `StatusTransitionPolicy`.

Transition table (identical to `malware_intel`'s
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

from campaign_intel.domain.exceptions.domain_exceptions import (
    InvalidLifecycleTransitionError,
)
from campaign_intel.domain.value_objects.enums import CampaignLifecycleStatus

_ALLOWED_TRANSITIONS: dict[CampaignLifecycleStatus, frozenset[CampaignLifecycleStatus]] = {
    CampaignLifecycleStatus.ACTIVE: frozenset(
        {
            CampaignLifecycleStatus.DEPRECATED,
            CampaignLifecycleStatus.REVOKED,
            CampaignLifecycleStatus.SUPERSEDED,
        }
    ),
    CampaignLifecycleStatus.DEPRECATED: frozenset(
        {
            CampaignLifecycleStatus.REVOKED,
            CampaignLifecycleStatus.ACTIVE,
        }
    ),
    CampaignLifecycleStatus.SUPERSEDED: frozenset({CampaignLifecycleStatus.REVOKED}),
    CampaignLifecycleStatus.REVOKED: frozenset(),
}


class LifecycleTransitionPolicy:
    @staticmethod
    def assert_legal_transition(
        current: CampaignLifecycleStatus, target: CampaignLifecycleStatus
    ) -> None:
        if target not in _ALLOWED_TRANSITIONS[current]:
            raise InvalidLifecycleTransitionError(current.value, target.value)
