"""Domain events for the Prompt & Payload Engine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class PayloadEvent:
    """Base class for all Payload Engine events."""

    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class TemplateCreated(PayloadEvent):
    """A new payload template was created."""

    template_id: str
    name: str
    template_type: str


@dataclass(frozen=True, slots=True)
class TemplatePublished(PayloadEvent):
    """A template was published (usable for rendering)."""

    template_id: str
    version: str


@dataclass(frozen=True, slots=True)
class TemplateArchived(PayloadEvent):
    """A template was archived."""

    template_id: str


def _now() -> datetime:
    return utc_now()
