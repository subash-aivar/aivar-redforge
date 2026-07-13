"""Domain events for the Knowledge bounded context."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class KnowledgeEvent:
    """Base class for all Knowledge domain events."""

    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class KnowledgeItemCreated(KnowledgeEvent):
    """A new knowledge item was created."""

    item_id: str
    title: str
    category: str


@dataclass(frozen=True, slots=True)
class KnowledgeItemPublished(KnowledgeEvent):
    """A knowledge item was published (available for use)."""

    item_id: str
    version: str


@dataclass(frozen=True, slots=True)
class KnowledgeItemArchived(KnowledgeEvent):
    """A knowledge item was archived."""

    item_id: str


@dataclass(frozen=True, slots=True)
class KnowledgeItemSuperseded(KnowledgeEvent):
    """A knowledge item was superseded by a newer version."""

    item_id: str
    superseded_by: str


def _now() -> datetime:
    return utc_now()
