from __future__ import annotations

import pytest

from attack_pattern_intel.domain.exceptions.domain_exceptions import (
    DuplicateAttackPatternError,
    InvalidLifecycleTransitionError,
)
from attack_pattern_intel.domain.policies.identity_policy import IdentityDedupPolicy
from attack_pattern_intel.domain.policies.lifecycle_transition_policy import (
    LifecycleTransitionPolicy,
)
from attack_pattern_intel.domain.value_objects.enums import TechniqueLifecycleStatus
from attack_pattern_intel.domain.value_objects.mitre_technique_ref import MitreTechniqueRef

ACTIVE = TechniqueLifecycleStatus.ACTIVE
DEPRECATED = TechniqueLifecycleStatus.DEPRECATED
SUPERSEDED = TechniqueLifecycleStatus.SUPERSEDED
REVOKED = TechniqueLifecycleStatus.REVOKED


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (ACTIVE, DEPRECATED),
        (ACTIVE, REVOKED),
        (ACTIVE, SUPERSEDED),
        (DEPRECATED, REVOKED),
        (DEPRECATED, ACTIVE),
        (SUPERSEDED, REVOKED),
    ],
)
def test_legal_transitions(
    current: TechniqueLifecycleStatus, target: TechniqueLifecycleStatus
) -> None:
    LifecycleTransitionPolicy.assert_legal_transition(current, target)


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (ACTIVE, ACTIVE),
        (DEPRECATED, SUPERSEDED),
        (SUPERSEDED, ACTIVE),
        (SUPERSEDED, DEPRECATED),
        (REVOKED, ACTIVE),
        (REVOKED, DEPRECATED),
        (REVOKED, SUPERSEDED),
    ],
)
def test_illegal_transitions(
    current: TechniqueLifecycleStatus, target: TechniqueLifecycleStatus
) -> None:
    with pytest.raises(InvalidLifecycleTransitionError):
        LifecycleTransitionPolicy.assert_legal_transition(current, target)


class _FakePattern:
    def __init__(self, ref: MitreTechniqueRef) -> None:
        self.mitre_technique_ref = ref


def test_identity_dedup_policy_allows_distinct_techniques() -> None:
    existing = [_FakePattern(MitreTechniqueRef("T1059"))]
    IdentityDedupPolicy.assert_no_duplicate(existing, MitreTechniqueRef("T1055"))  # type: ignore[arg-type]


def test_identity_dedup_policy_rejects_duplicate() -> None:
    existing = [_FakePattern(MitreTechniqueRef("T1059", "T1059.001"))]
    with pytest.raises(DuplicateAttackPatternError):
        IdentityDedupPolicy.assert_no_duplicate(existing, MitreTechniqueRef("T1059", "T1059.001"))  # type: ignore[arg-type]
