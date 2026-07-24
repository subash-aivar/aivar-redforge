from __future__ import annotations

import pytest

from siem_storage.domain.exceptions.domain_exceptions import (
    InvalidRetentionDurationError,
    NoTransitionFromArchiveError,
    UnknownCategoryError,
)
from siem_storage.domain.value_objects.enums import StorageTier
from siem_storage.domain.value_objects.retention import (
    RetentionDuration,
    RetentionPolicy,
    next_tier,
)


def test_retention_duration_rejects_zero_days() -> None:
    with pytest.raises(InvalidRetentionDurationError):
        RetentionDuration(days=0)


def test_retention_duration_rejects_negative_days() -> None:
    with pytest.raises(InvalidRetentionDurationError):
        RetentionDuration(days=-5)


def test_retention_duration_accepts_positive_days() -> None:
    assert RetentionDuration(days=30).days == 30


@pytest.mark.parametrize(
    ("current", "expected"),
    [
        (StorageTier.HOT, StorageTier.WARM),
        (StorageTier.WARM, StorageTier.COLD),
        (StorageTier.COLD, StorageTier.ARCHIVE),
        (StorageTier.ARCHIVE, None),
    ],
)
def test_next_tier_progression(current: StorageTier, expected: StorageTier | None) -> None:
    assert next_tier(current) == expected


def test_policy_duration_for_known_category() -> None:
    policy = RetentionPolicy(
        tenant_id="t-1",
        durations_by_category={
            "authentication": {StorageTier.HOT: RetentionDuration(days=30)},
        },
    )
    assert policy.duration_for("authentication", StorageTier.HOT).days == 30


def test_policy_duration_for_unknown_category_raises() -> None:
    policy = RetentionPolicy(tenant_id="t-1")
    with pytest.raises(UnknownCategoryError):
        policy.duration_for("network", StorageTier.HOT)


def test_policy_duration_for_configured_category_missing_tier_raises() -> None:
    policy = RetentionPolicy(
        tenant_id="t-1",
        durations_by_category={"authentication": {StorageTier.HOT: RetentionDuration(days=30)}},
    )
    with pytest.raises(UnknownCategoryError):
        policy.duration_for("authentication", StorageTier.COLD)


def test_policy_next_tier_for_hot_returns_warm() -> None:
    policy = RetentionPolicy(tenant_id="t-1")
    assert policy.next_tier_for(StorageTier.HOT) == StorageTier.WARM


def test_policy_next_tier_for_cold_returns_archive() -> None:
    policy = RetentionPolicy(tenant_id="t-1")
    assert policy.next_tier_for(StorageTier.COLD) == StorageTier.ARCHIVE


def test_policy_next_tier_for_archive_raises() -> None:
    """ARCHIVE is the terminal, source-of-truth tier (M37 §4/§14, M43E)
    — there is no further transition, and this must be a raised error,
    not a silently-swallowed no-op."""
    policy = RetentionPolicy(tenant_id="t-1")
    with pytest.raises(NoTransitionFromArchiveError):
        policy.next_tier_for(StorageTier.ARCHIVE)
