"""Retention policy value objects (M37 §4).

`RetentionPolicy` is tenant-scoped, per-category, per-tier durations —
"policy as data, not code" (the same pattern this platform already uses
for `RetentionPolicy`-shaped configuration elsewhere). Enforcement
(the scheduled worker emitting `RetentionTierTransitioned`/
`RetentionExpired`) is an application-layer concern, added in a later
phase — this is the pure policy shape and its query/transition logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from siem_storage.domain.exceptions.domain_exceptions import (
    InvalidRetentionDurationError,
    NoTransitionFromArchiveError,
    UnknownCategoryError,
)
from siem_storage.domain.value_objects.enums import StorageTier

_TIER_ORDER: tuple[StorageTier, StorageTier, StorageTier, StorageTier] = (
    StorageTier.HOT,
    StorageTier.WARM,
    StorageTier.COLD,
    StorageTier.ARCHIVE,
)


@dataclass(frozen=True, slots=True)
class RetentionDuration:
    """A positive number of days a category is retained in a given tier."""

    days: int

    def __post_init__(self) -> None:
        if self.days <= 0:
            raise InvalidRetentionDurationError(self.days)


def next_tier(current: StorageTier) -> StorageTier | None:
    """The next tier in the hot → warm → cold → archive lifecycle, or
    `None` once `ARCHIVE` (the terminal, source-of-truth tier per M37
    §4/§14, M43E) is reached."""
    index = _TIER_ORDER.index(current)
    if index + 1 >= len(_TIER_ORDER):
        return None
    return _TIER_ORDER[index + 1]


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    """Per-category, per-tier retention durations for one tenant."""

    tenant_id: str
    durations_by_category: dict[str, dict[StorageTier, RetentionDuration]] = field(
        default_factory=dict
    )

    def duration_for(self, category: str, tier: StorageTier) -> RetentionDuration:
        by_tier = self.durations_by_category.get(category)
        if by_tier is None or tier not in by_tier:
            raise UnknownCategoryError(category)
        return by_tier[tier]

    def next_tier_for(self, current: StorageTier) -> StorageTier:
        """Same as the module-level `next_tier`, raising instead of
        returning `None` when already at the terminal tier — the shape
        an enforcement worker actually needs (it should not be asked to
        transition an already-terminal event)."""
        target = next_tier(current)
        if target is None:
            raise NoTransitionFromArchiveError()
        return target
