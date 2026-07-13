"""Domain events for the Provider Adapter Framework."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class ProviderEvent:
    """Base class for all Provider Framework events."""

    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class ProviderRegistered(ProviderEvent):
    """A new provider was registered."""

    provider_id: str
    name: str
    provider_type: str


@dataclass(frozen=True, slots=True)
class ProviderHealthChanged(ProviderEvent):
    """A provider's health status changed."""

    provider_id: str
    old_status: str
    new_status: str


@dataclass(frozen=True, slots=True)
class ProviderDeregistered(ProviderEvent):
    """A provider was removed from the registry."""

    provider_id: str


def _now() -> datetime:
    return utc_now()
