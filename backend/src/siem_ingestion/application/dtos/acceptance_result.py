"""Immutable acceptance-result DTOs for the Event Ingestion Pipeline.

These are read-once outcomes returned synchronously to the caller —
never persisted (the pipeline's responsibility ends at producing a
validated `CanonicalEvent`; what happens to the *result object* itself
is the caller's concern, not this bounded context's).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from siem_shared.domain.value_objects.canonical_event import CanonicalEvent


class AcceptanceStatus(StrEnum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    PARTIALLY_ACCEPTED = "partially_accepted"
    VALIDATION_FAILED = "validation_failed"
    RATE_LIMITED = "rate_limited"


@dataclass(frozen=True, slots=True)
class ValidationFailure:
    """One pipeline-stage failure — `stage` names the validation stage
    (M43C §3), `error_type` is the raised exception's class name,
    `message` is the human-readable detail."""

    stage: str
    error_type: str
    message: str


@dataclass(frozen=True, slots=True)
class EventAcceptanceResult:
    status: AcceptanceStatus
    canonical_event: CanonicalEvent | None = None
    failures: tuple[ValidationFailure, ...] = ()

    def __post_init__(self) -> None:
        if self.status == AcceptanceStatus.ACCEPTED and self.canonical_event is None:
            raise ValueError("ACCEPTED EventAcceptanceResult must carry a canonical_event")
        if self.status != AcceptanceStatus.ACCEPTED and self.canonical_event is not None:
            raise ValueError("Only an ACCEPTED EventAcceptanceResult may carry a canonical_event")


@dataclass(frozen=True, slots=True)
class BatchAcceptanceResult:
    status: AcceptanceStatus
    results: tuple[EventAcceptanceResult, ...] = field(default_factory=tuple)

    @property
    def accepted_count(self) -> int:
        return sum(1 for r in self.results if r.status == AcceptanceStatus.ACCEPTED)

    @property
    def rejected_count(self) -> int:
        return len(self.results) - self.accepted_count

    @property
    def accepted_events(self) -> tuple[CanonicalEvent, ...]:
        return tuple(
            r.canonical_event
            for r in self.results
            if r.status == AcceptanceStatus.ACCEPTED and r.canonical_event is not None
        )
