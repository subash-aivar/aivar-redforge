"""Lifecycle-transition validation (M43E §4/§6).

A storage lifecycle transition is valid only if it advances exactly one
step forward (hot → warm → cold → archive) — never skipping a tier and
never moving backward. This reuses `siem_storage.domain.value_objects
.retention.next_tier` (M43A/M43E's own domain rule) rather than
duplicating the tier-ordering logic in the application layer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from siem_storage.application.exceptions import InvalidLifecycleTransitionError
from siem_storage.domain.value_objects.retention import next_tier

if TYPE_CHECKING:
    from siem_storage.domain.value_objects.enums import StorageTier


def validate_lifecycle_transition(current: StorageTier, target: StorageTier) -> None:
    expected = next_tier(current)
    if expected is None or target != expected:
        raise InvalidLifecycleTransitionError(current, target)
