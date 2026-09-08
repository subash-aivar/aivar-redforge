from __future__ import annotations

from datetime import UTC, datetime

import pytest

from campaign_intel.domain.aggregates.campaign import Campaign
from campaign_intel.domain.exceptions.domain_exceptions import (
    DuplicateCampaignError,
    InvalidLifecycleTransitionError,
    InvalidStatusTransitionError,
)
from campaign_intel.domain.policies.identity_policy import CampaignIdentityPolicy
from campaign_intel.domain.policies.lifecycle_transition_policy import (
    LifecycleTransitionPolicy,
)
from campaign_intel.domain.policies.status_transition_policy import StatusTransitionPolicy
from campaign_intel.domain.value_objects.enums import (
    CampaignLifecycleStatus,
    CampaignStatus,
)
from campaign_intel.domain.value_objects.identifiers import CampaignId, TenantId

NOW = datetime(2026, 8, 5, tzinfo=UTC)

ACTIVE = CampaignLifecycleStatus.ACTIVE
DEPRECATED = CampaignLifecycleStatus.DEPRECATED
REVOKED = CampaignLifecycleStatus.REVOKED
SUPERSEDED = CampaignLifecycleStatus.SUPERSEDED

LEGAL_LIFECYCLE = [
    (ACTIVE, DEPRECATED),
    (ACTIVE, REVOKED),
    (ACTIVE, SUPERSEDED),
    (DEPRECATED, REVOKED),
    (DEPRECATED, ACTIVE),
    (SUPERSEDED, REVOKED),
]
ILLEGAL_LIFECYCLE = [
    (ACTIVE, ACTIVE),
    (DEPRECATED, DEPRECATED),
    (DEPRECATED, SUPERSEDED),
    (SUPERSEDED, ACTIVE),
    (SUPERSEDED, DEPRECATED),
    (SUPERSEDED, SUPERSEDED),
    (REVOKED, ACTIVE),
    (REVOKED, DEPRECATED),
    (REVOKED, REVOKED),
    (REVOKED, SUPERSEDED),
]

UNKNOWN = CampaignStatus.UNKNOWN
ONGOING = CampaignStatus.ONGOING
SUSPECTED = CampaignStatus.SUSPECTED_CONCLUDED
CONCLUDED = CampaignStatus.CONCLUDED

LEGAL_STATUS = [
    (UNKNOWN, ONGOING),
    (UNKNOWN, SUSPECTED),
    (UNKNOWN, CONCLUDED),
    (ONGOING, SUSPECTED),
    (ONGOING, CONCLUDED),
    (SUSPECTED, ONGOING),
    (SUSPECTED, CONCLUDED),
]
ILLEGAL_STATUS = [
    (UNKNOWN, UNKNOWN),
    (ONGOING, UNKNOWN),
    (ONGOING, ONGOING),
    (SUSPECTED, UNKNOWN),
    (SUSPECTED, SUSPECTED),
    (CONCLUDED, UNKNOWN),
    (CONCLUDED, ONGOING),
    (CONCLUDED, SUSPECTED),
    (CONCLUDED, CONCLUDED),
]


def _make(tenant_id: TenantId | None, canonical_name: str) -> Campaign:
    return Campaign.observe(
        campaign_id=CampaignId.generate(),
        tenant_id=tenant_id,
        canonical_name=canonical_name,
        now=NOW,
    )


# ── Record lifecycle table ──────────────────────────────────────────────


@pytest.mark.parametrize(("current", "target"), LEGAL_LIFECYCLE)
def test_legal_lifecycle_transitions_are_allowed(
    current: CampaignLifecycleStatus, target: CampaignLifecycleStatus
) -> None:
    LifecycleTransitionPolicy.assert_legal_transition(current, target)


@pytest.mark.parametrize(("current", "target"), ILLEGAL_LIFECYCLE)
def test_illegal_lifecycle_transitions_raise(
    current: CampaignLifecycleStatus, target: CampaignLifecycleStatus
) -> None:
    with pytest.raises(InvalidLifecycleTransitionError):
        LifecycleTransitionPolicy.assert_legal_transition(current, target)


def test_lifecycle_table_covers_every_status() -> None:
    covered = {c for c, _ in LEGAL_LIFECYCLE} | {c for c, _ in ILLEGAL_LIFECYCLE}
    assert covered == set(CampaignLifecycleStatus)


def test_revoked_is_terminal() -> None:
    for target in CampaignLifecycleStatus:
        with pytest.raises(InvalidLifecycleTransitionError):
            LifecycleTransitionPolicy.assert_legal_transition(REVOKED, target)


# ── Real-world status table ─────────────────────────────────────────────


@pytest.mark.parametrize(("current", "target"), LEGAL_STATUS)
def test_legal_status_transitions_are_allowed(
    current: CampaignStatus, target: CampaignStatus
) -> None:
    StatusTransitionPolicy.assert_legal_transition(current, target)


@pytest.mark.parametrize(("current", "target"), ILLEGAL_STATUS)
def test_illegal_status_transitions_raise(current: CampaignStatus, target: CampaignStatus) -> None:
    with pytest.raises(InvalidStatusTransitionError):
        StatusTransitionPolicy.assert_legal_transition(current, target)


def test_status_table_covers_every_status() -> None:
    covered = {c for c, _ in LEGAL_STATUS} | {c for c, _ in ILLEGAL_STATUS}
    assert covered == set(CampaignStatus)


def test_concluded_is_terminal() -> None:
    for target in CampaignStatus:
        with pytest.raises(InvalidStatusTransitionError):
            StatusTransitionPolicy.assert_legal_transition(CONCLUDED, target)


def test_the_two_policies_are_separate_objects_with_separate_errors() -> None:
    assert LifecycleTransitionPolicy is not StatusTransitionPolicy
    with pytest.raises(InvalidStatusTransitionError):
        StatusTransitionPolicy.assert_legal_transition(CONCLUDED, ONGOING)
    with pytest.raises(InvalidLifecycleTransitionError):
        LifecycleTransitionPolicy.assert_legal_transition(REVOKED, ACTIVE)


# ── Identity ────────────────────────────────────────────────────────────


def test_identity_policy_rejects_duplicate_canonical_name() -> None:
    existing = [_make(None, "cloud hopper")]
    with pytest.raises(DuplicateCampaignError):
        CampaignIdentityPolicy.assert_no_duplicate(existing, "cloud hopper")


def test_identity_policy_allows_distinct_canonical_name() -> None:
    existing = [_make(None, "cloud hopper")]
    CampaignIdentityPolicy.assert_no_duplicate(existing, "operation aurora")


def test_identity_policy_on_empty_scope_is_a_noop() -> None:
    CampaignIdentityPolicy.assert_no_duplicate([], "cloud hopper")
