"""Domain events for the Validation bounded context."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class ValidationEvent:
    """Base class for all Validation Run domain events."""

    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class ValidationScheduled(ValidationEvent):
    """A validation run was scheduled for execution."""

    run_id: str
    target_id: str
    organization_id: str
    trigger_type: str


@dataclass(frozen=True, slots=True)
class ValidationStarted(ValidationEvent):
    """A validation run began executing."""

    run_id: str
    target_id: str


@dataclass(frozen=True, slots=True)
class ValidationCompleted(ValidationEvent):
    """A validation run finished successfully."""

    run_id: str
    target_id: str
    total_checks: int
    passed: int
    failed: int


@dataclass(frozen=True, slots=True)
class ValidationFailed(ValidationEvent):
    """A validation run terminated due to an error."""

    run_id: str
    target_id: str
    reason: str


@dataclass(frozen=True, slots=True)
class ValidationCancelled(ValidationEvent):
    """A validation run was cancelled."""

    run_id: str
    target_id: str


@dataclass(frozen=True, slots=True)
class ValidationRetried(ValidationEvent):
    """A failed validation run was retried (new run created)."""

    run_id: str
    original_run_id: str
    target_id: str


def _now() -> datetime:
    """Internal helper for event timestamp generation."""
    return utc_now()
