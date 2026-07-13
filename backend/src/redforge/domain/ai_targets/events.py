"""Domain events for the AI Target bounded context."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class TargetEvent:
    """Base class for all AI Target domain events."""

    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class TargetRegistered(TargetEvent):
    """A new AI Target was registered."""

    target_id: str
    organization_id: str
    name: str
    target_type: str
    provider: str


@dataclass(frozen=True, slots=True)
class TargetRenamed(TargetEvent):
    """An AI Target's display name was changed."""

    target_id: str
    old_name: str
    new_name: str


@dataclass(frozen=True, slots=True)
class TargetActivated(TargetEvent):
    """An AI Target was activated for validation."""

    target_id: str


@dataclass(frozen=True, slots=True)
class TargetDeactivated(TargetEvent):
    """An AI Target was deactivated."""

    target_id: str


@dataclass(frozen=True, slots=True)
class TargetArchived(TargetEvent):
    """An AI Target was archived (permanently retired)."""

    target_id: str


@dataclass(frozen=True, slots=True)
class TargetRestored(TargetEvent):
    """An archived AI Target was restored to inactive state."""

    target_id: str


@dataclass(frozen=True, slots=True)
class TargetProviderChanged(TargetEvent):
    """An AI Target's provider was changed."""

    target_id: str
    old_provider: str
    new_provider: str


@dataclass(frozen=True, slots=True)
class TargetEndpointChanged(TargetEvent):
    """An AI Target's endpoint URL was changed."""

    target_id: str
    old_endpoint: str
    new_endpoint: str


@dataclass(frozen=True, slots=True)
class ValidationPolicyAttached(TargetEvent):
    """A validation policy was attached to an AI Target."""

    target_id: str
    policy_id: str


@dataclass(frozen=True, slots=True)
class ValidationPolicyDetached(TargetEvent):
    """A validation policy was detached from an AI Target."""

    target_id: str
    policy_id: str


def _now() -> datetime:
    """Internal helper for event timestamp generation."""
    return utc_now()
