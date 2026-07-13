"""Domain events for the Attack Library bounded context."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class AttackLibraryEvent:
    """Base class for all Attack Library domain events."""

    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class AttackCreated(AttackLibraryEvent):
    """A new attack definition was created."""

    attack_id: str
    name: str
    category: str


@dataclass(frozen=True, slots=True)
class AttackPublished(AttackLibraryEvent):
    """An attack was published (available for execution)."""

    attack_id: str
    version: str


@dataclass(frozen=True, slots=True)
class AttackDeprecated(AttackLibraryEvent):
    """An attack was deprecated (still usable but discouraged)."""

    attack_id: str


@dataclass(frozen=True, slots=True)
class AttackArchived(AttackLibraryEvent):
    """An attack was archived (no longer executable)."""

    attack_id: str


@dataclass(frozen=True, slots=True)
class AttackSuperseded(AttackLibraryEvent):
    """An attack was superseded by a newer definition."""

    attack_id: str
    superseded_by: str


def _now() -> datetime:
    return utc_now()
