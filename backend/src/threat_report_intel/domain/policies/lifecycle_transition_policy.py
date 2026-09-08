"""LifecycleTransitionPolicy — the legal
`ThreatReportLifecycleStatus` transition table.

This governs RedForge's OWN RECORD lifecycle only — it says nothing
about whether the publisher has withdrawn or amended the underlying
publication.

Transition table (identical to `campaign_intel`'s, `malware_intel`'s,
`tool_intel`'s and `infrastructure_intel`'s `LifecycleTransitionPolicy`,
enforced here — the single source of truth, not merely a docstring
elsewhere):

    ACTIVE     -> {DEPRECATED, REVOKED, SUPERSEDED}
    DEPRECATED -> {REVOKED, ACTIVE}   (ACTIVE = reactivate)
    SUPERSEDED -> {REVOKED}
    REVOKED    -> {}                  (terminal — no transitions out)

`SUPERSEDED` additionally requires a `superseded_by` id — enforced by
the aggregate, not this policy (this policy only knows about the
enum-state graph).
"""

from __future__ import annotations

from threat_report_intel.domain.exceptions.domain_exceptions import (
    InvalidLifecycleTransitionError,
)
from threat_report_intel.domain.value_objects.enums import ThreatReportLifecycleStatus

_ALLOWED_TRANSITIONS: dict[ThreatReportLifecycleStatus, frozenset[ThreatReportLifecycleStatus]] = {
    ThreatReportLifecycleStatus.ACTIVE: frozenset(
        {
            ThreatReportLifecycleStatus.DEPRECATED,
            ThreatReportLifecycleStatus.REVOKED,
            ThreatReportLifecycleStatus.SUPERSEDED,
        }
    ),
    ThreatReportLifecycleStatus.DEPRECATED: frozenset(
        {
            ThreatReportLifecycleStatus.REVOKED,
            ThreatReportLifecycleStatus.ACTIVE,
        }
    ),
    ThreatReportLifecycleStatus.SUPERSEDED: frozenset({ThreatReportLifecycleStatus.REVOKED}),
    ThreatReportLifecycleStatus.REVOKED: frozenset(),
}


class LifecycleTransitionPolicy:
    @staticmethod
    def assert_legal_transition(
        current: ThreatReportLifecycleStatus, target: ThreatReportLifecycleStatus
    ) -> None:
        if target not in _ALLOWED_TRANSITIONS[current]:
            raise InvalidLifecycleTransitionError(current.value, target.value)
