from __future__ import annotations

import pytest

from threat_report_intel.domain.exceptions.domain_exceptions import (
    DuplicateThreatReportError,
    InvalidLifecycleTransitionError,
)
from threat_report_intel.domain.policies.identity_policy import ThreatReportIdentityPolicy
from threat_report_intel.domain.policies.lifecycle_transition_policy import (
    LifecycleTransitionPolicy,
)
from threat_report_intel.domain.value_objects.enums import ThreatReportLifecycleStatus

S = ThreatReportLifecycleStatus

LEGAL = [
    (S.ACTIVE, S.DEPRECATED),
    (S.ACTIVE, S.REVOKED),
    (S.ACTIVE, S.SUPERSEDED),
    (S.DEPRECATED, S.REVOKED),
    (S.DEPRECATED, S.ACTIVE),
    (S.SUPERSEDED, S.REVOKED),
]

ILLEGAL = [
    (S.ACTIVE, S.ACTIVE),
    (S.DEPRECATED, S.DEPRECATED),
    (S.DEPRECATED, S.SUPERSEDED),
    (S.SUPERSEDED, S.ACTIVE),
    (S.SUPERSEDED, S.DEPRECATED),
    (S.REVOKED, S.ACTIVE),
    (S.REVOKED, S.DEPRECATED),
    (S.REVOKED, S.SUPERSEDED),
    (S.REVOKED, S.REVOKED),
]


@pytest.mark.parametrize(("current", "target"), LEGAL)
def test_legal_transitions_are_allowed(current, target) -> None:
    LifecycleTransitionPolicy.assert_legal_transition(current, target)


@pytest.mark.parametrize(("current", "target"), ILLEGAL)
def test_illegal_transitions_are_rejected(current, target) -> None:
    with pytest.raises(InvalidLifecycleTransitionError):
        LifecycleTransitionPolicy.assert_legal_transition(current, target)


def test_the_transition_table_matches_every_prior_intel_context_exactly() -> None:
    """ACTIVE -> {DEPRECATED, REVOKED, SUPERSEDED};
    DEPRECATED -> {REVOKED, ACTIVE}; SUPERSEDED -> {REVOKED};
    REVOKED -> {} (terminal)."""
    legal = {(c, t) for c in S for t in S if (c, t) in LEGAL}
    assert legal == set(LEGAL)
    assert not [t for t in S if (S.REVOKED, t) in LEGAL]


class _Fake:
    def __init__(self, canonical_title: str) -> None:
        self.canonical_title = canonical_title


def test_identity_policy_detects_a_duplicate_canonical_title() -> None:
    existing = [_Fake("operation cloud hopper")]
    with pytest.raises(DuplicateThreatReportError):
        ThreatReportIdentityPolicy.assert_no_duplicate(
            existing,  # type: ignore[arg-type]
            "operation cloud hopper",
        )


def test_identity_policy_permits_a_distinct_canonical_title() -> None:
    existing = [_Fake("operation cloud hopper")]
    ThreatReportIdentityPolicy.assert_no_duplicate(
        existing,  # type: ignore[arg-type]
        "operation soft cell",
    )


def test_identity_policy_permits_an_empty_scope() -> None:
    ThreatReportIdentityPolicy.assert_no_duplicate([], "anything")
