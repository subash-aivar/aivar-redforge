from __future__ import annotations

import pytest

from siem_storage.application.exceptions import InvalidLifecycleTransitionError
from siem_storage.application.services.lifecycle_validation import validate_lifecycle_transition
from siem_storage.domain.value_objects.enums import StorageTier


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (StorageTier.HOT, StorageTier.WARM),
        (StorageTier.WARM, StorageTier.COLD),
        (StorageTier.COLD, StorageTier.ARCHIVE),
    ],
)
def test_valid_single_step_forward_transition(current: StorageTier, target: StorageTier) -> None:
    validate_lifecycle_transition(current, target)


def test_skipping_a_tier_is_invalid() -> None:
    with pytest.raises(InvalidLifecycleTransitionError):
        validate_lifecycle_transition(StorageTier.HOT, StorageTier.COLD)


def test_backward_transition_is_invalid() -> None:
    with pytest.raises(InvalidLifecycleTransitionError):
        validate_lifecycle_transition(StorageTier.WARM, StorageTier.HOT)


def test_transition_from_terminal_archive_is_invalid() -> None:
    with pytest.raises(InvalidLifecycleTransitionError):
        validate_lifecycle_transition(StorageTier.ARCHIVE, StorageTier.HOT)


def test_self_transition_is_invalid() -> None:
    with pytest.raises(InvalidLifecycleTransitionError):
        validate_lifecycle_transition(StorageTier.HOT, StorageTier.HOT)
