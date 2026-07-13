"""Domain events for the Validation Policy bounded context."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class PolicyEvent:
    """Base class for all Validation Policy domain events."""

    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class PolicyCreated(PolicyEvent):
    """A new validation policy was created."""

    policy_id: str
    name: str


@dataclass(frozen=True, slots=True)
class PolicyPublished(PolicyEvent):
    """A policy was published (available for execution)."""

    policy_id: str
    version: str
    attack_count: int


@dataclass(frozen=True, slots=True)
class PolicyArchived(PolicyEvent):
    """A policy was archived."""

    policy_id: str


@dataclass(frozen=True, slots=True)
class PolicySuperseded(PolicyEvent):
    """A policy was superseded by a newer version."""

    policy_id: str
    superseded_by: str


def _now() -> datetime:
    return utc_now()
