"""Immutable normalization-result DTOs (M43D §7).

Read-once outcomes returned synchronously to the caller — never
persisted. `NORMALIZED` additionally carries the `EventsNormalized`
domain event (M37 §2.4) that was raised for it; every non-`NORMALIZED`
outcome besides pre-lookup validation/registry-selection failures
carries the `NormalizationFailed` domain event instead — both are
M43A's existing domain events, exercised here for the first time rather
than duplicated.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from siem_normalization.domain.events.normalization_events import (
        EventsNormalized,
        NormalizationFailed,
    )
    from siem_shared.domain.value_objects.canonical_event import CanonicalEvent


class NormalizationStatus(StrEnum):
    NORMALIZED = "normalized"
    REJECTED = "rejected"
    UNSUPPORTED_PROVIDER = "unsupported_provider"
    UNSUPPORTED_VERSION = "unsupported_version"
    AMBIGUOUS_REGISTRATION = "ambiguous_registration"
    FAILED_NORMALIZATION = "failed_normalization"
    PARTIALLY_NORMALIZED = "partially_normalized"


@dataclass(frozen=True, slots=True)
class NormalizationFailure:
    stage: str
    error_type: str
    message: str


@dataclass(frozen=True, slots=True)
class NormalizationResult:
    status: NormalizationStatus
    canonical_event: CanonicalEvent | None = None
    normalized_domain_event: EventsNormalized | None = None
    failed_domain_event: NormalizationFailed | None = None
    failures: tuple[NormalizationFailure, ...] = ()

    def __post_init__(self) -> None:
        if self.status == NormalizationStatus.NORMALIZED:
            if self.canonical_event is None:
                raise ValueError("NORMALIZED NormalizationResult must carry a canonical_event")
            if self.failed_domain_event is not None:
                raise ValueError(
                    "NORMALIZED NormalizationResult cannot carry a failed_domain_event"
                )
        else:
            if self.canonical_event is not None:
                raise ValueError(
                    "Only a NORMALIZED NormalizationResult may carry a canonical_event"
                )
            if self.normalized_domain_event is not None:
                raise ValueError(
                    "Only a NORMALIZED NormalizationResult may carry a normalized_domain_event"
                )


@dataclass(frozen=True, slots=True)
class BatchNormalizationResult:
    status: NormalizationStatus
    results: tuple[NormalizationResult, ...] = field(default_factory=tuple)

    @property
    def normalized_count(self) -> int:
        return sum(1 for r in self.results if r.status == NormalizationStatus.NORMALIZED)

    @property
    def failed_count(self) -> int:
        return len(self.results) - self.normalized_count

    @property
    def normalized_events(self) -> tuple[CanonicalEvent, ...]:
        return tuple(
            r.canonical_event
            for r in self.results
            if r.status == NormalizationStatus.NORMALIZED and r.canonical_event is not None
        )
