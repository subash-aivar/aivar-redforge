from __future__ import annotations

import contextlib

import pytest

from infrastructure_intel.domain.exceptions.domain_exceptions import (
    DuplicateInfrastructureError,
    InvalidLifecycleTransitionError,
)
from infrastructure_intel.domain.factories.infrastructure_factory import (
    InfrastructureFactory,
)
from infrastructure_intel.domain.policies.identity_policy import (
    InfrastructureIdentityPolicy,
)
from infrastructure_intel.domain.policies.lifecycle_transition_policy import (
    LifecycleTransitionPolicy,
)
from infrastructure_intel.domain.value_objects.enums import (
    InfrastructureLifecycleStatus,
    InfrastructureType,
)

S = InfrastructureLifecycleStatus
T = InfrastructureType

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


def test_identity_policy_rejects_a_duplicate_identity(now) -> None:
    factory = InfrastructureFactory()
    existing = factory.observe(
        tenant_id=None, infrastructure_type=T.ASN, normalized_identifier="AS15169", now=now
    )
    with pytest.raises(DuplicateInfrastructureError):
        InfrastructureIdentityPolicy.assert_no_duplicate([existing], T.ASN, "AS15169")


def test_identity_policy_allows_a_distinct_identifier(now) -> None:
    factory = InfrastructureFactory()
    existing = factory.observe(
        tenant_id=None, infrastructure_type=T.ASN, normalized_identifier="AS15169", now=now
    )
    InfrastructureIdentityPolicy.assert_no_duplicate([existing], T.ASN, "AS64512")


def test_identity_policy_treats_the_type_as_part_of_the_identity(now) -> None:
    """The same normalized string under a different
    `infrastructure_type` is a legitimately different record."""
    factory = InfrastructureFactory()
    existing = factory.observe(
        tenant_id=None,
        infrastructure_type=T.DOMAIN,
        normalized_identifier="evil.example.com",
        now=now,
    )
    InfrastructureIdentityPolicy.assert_no_duplicate(
        [existing], T.HOSTING_PROVIDER, "evil.example.com"
    )
    with pytest.raises(DuplicateInfrastructureError):
        InfrastructureIdentityPolicy.assert_no_duplicate([existing], T.DOMAIN, "evil.example.com")


def test_identity_policy_allows_an_empty_scope() -> None:
    InfrastructureIdentityPolicy.assert_no_duplicate([], T.ASN, "AS15169")
