"""Domain events for the Finding bounded context."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class FindingEvent:
    """Base class for all Finding domain events."""

    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class FindingCreated(FindingEvent):
    """A new Finding was generated from evidence."""

    finding_id: str
    target_id: str
    severity: str
    title: str


@dataclass(frozen=True, slots=True)
class FindingClosed(FindingEvent):
    """A Finding was closed (resolved or mitigated)."""

    finding_id: str


@dataclass(frozen=True, slots=True)
class FindingReopened(FindingEvent):
    """A previously closed Finding was reopened."""

    finding_id: str


@dataclass(frozen=True, slots=True)
class FindingRiskAccepted(FindingEvent):
    """Risk was accepted for a Finding."""

    finding_id: str


def _now() -> datetime:
    """Internal helper for event timestamp generation."""
    return utc_now()
