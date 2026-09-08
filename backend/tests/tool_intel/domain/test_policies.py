from __future__ import annotations

import contextlib

import pytest

from tool_intel.domain.exceptions.domain_exceptions import (
    DuplicateToolError,
    InvalidLifecycleTransitionError,
)
from tool_intel.domain.factories.tool_factory import ToolFactory
from tool_intel.domain.policies.identity_policy import ToolIdentityPolicy
from tool_intel.domain.policies.lifecycle_transition_policy import (
    LifecycleTransitionPolicy,
)
from tool_intel.domain.value_objects.enums import ToolLifecycleStatus

S = ToolLifecycleStatus

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
    (S.SUPERSEDED, S.SUPERSEDED),
    (S.REVOKED, S.ACTIVE),
    (S.REVOKED, S.DEPRECATED),
    (S.REVOKED, S.REVOKED),
    (S.REVOKED, S.SUPERSEDED),
]


@pytest.mark.parametrize(("current", "target"), LEGAL)
def test_legal_lifecycle_transitions_are_allowed(current: S, target: S) -> None:
    LifecycleTransitionPolicy.assert_legal_transition(current, target)


@pytest.mark.parametrize(("current", "target"), ILLEGAL)
def test_illegal_lifecycle_transitions_are_rejected(current: S, target: S) -> None:
    with pytest.raises(InvalidLifecycleTransitionError):
        LifecycleTransitionPolicy.assert_legal_transition(current, target)


def test_the_transition_table_is_exhaustive_over_the_enum() -> None:
    """Every state must have an entry — a missing key would raise
    KeyError rather than a domain error."""
    for state in S:
        for target in S:
            with contextlib.suppress(InvalidLifecycleTransitionError):
                LifecycleTransitionPolicy.assert_legal_transition(state, target)


def test_revoked_is_terminal() -> None:
    for target in S:
        with pytest.raises(InvalidLifecycleTransitionError):
            LifecycleTransitionPolicy.assert_legal_transition(S.REVOKED, target)


def test_identity_policy_rejects_a_duplicate_canonical_name(now) -> None:
    factory = ToolFactory()
    existing = factory.observe(tenant_id=None, canonical_name="mimikatz", now=now)
    with pytest.raises(DuplicateToolError):
        ToolIdentityPolicy.assert_no_duplicate([existing], "mimikatz")


def test_identity_policy_allows_a_distinct_canonical_name(now) -> None:
    factory = ToolFactory()
    existing = factory.observe(tenant_id=None, canonical_name="mimikatz", now=now)
    ToolIdentityPolicy.assert_no_duplicate([existing], "psexec")


def test_identity_policy_allows_an_empty_scope() -> None:
    ToolIdentityPolicy.assert_no_duplicate([], "mimikatz")
