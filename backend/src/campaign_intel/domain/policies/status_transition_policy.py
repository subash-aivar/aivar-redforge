"""StatusTransitionPolicy — the legal `CampaignStatus` transition table.

This governs the REAL-WORLD adversary campaign's own operational state,
a completely independent axis from RedForge's record lifecycle
(`LifecycleTransitionPolicy`). Deprecating a record says nothing about
whether the campaign concluded, and concluding a campaign says nothing
about whether the record is still trustworthy.

Transition table:

    UNKNOWN             -> {ONGOING, SUSPECTED_CONCLUDED, CONCLUDED}
    ONGOING             -> {SUSPECTED_CONCLUDED, CONCLUDED}
    SUSPECTED_CONCLUDED -> {ONGOING, CONCLUDED}
    CONCLUDED           -> {}   (terminal — no transitions out)
"""

from __future__ import annotations

from campaign_intel.domain.exceptions.domain_exceptions import (
    InvalidStatusTransitionError,
)
from campaign_intel.domain.value_objects.enums import CampaignStatus

_ALLOWED_TRANSITIONS: dict[CampaignStatus, frozenset[CampaignStatus]] = {
    CampaignStatus.UNKNOWN: frozenset(
        {
            CampaignStatus.ONGOING,
            CampaignStatus.SUSPECTED_CONCLUDED,
            CampaignStatus.CONCLUDED,
        }
    ),
    CampaignStatus.ONGOING: frozenset(
        {
            CampaignStatus.SUSPECTED_CONCLUDED,
            CampaignStatus.CONCLUDED,
        }
    ),
    CampaignStatus.SUSPECTED_CONCLUDED: frozenset(
        {
            CampaignStatus.ONGOING,
            CampaignStatus.CONCLUDED,
        }
    ),
    CampaignStatus.CONCLUDED: frozenset(),
}


class StatusTransitionPolicy:
    @staticmethod
    def assert_legal_transition(current: CampaignStatus, target: CampaignStatus) -> None:
        if target not in _ALLOWED_TRANSITIONS[current]:
            raise InvalidStatusTransitionError(current.value, target.value)
