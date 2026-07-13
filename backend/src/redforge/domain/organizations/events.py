"""Domain events for the Organization bounded context.

Domain events represent facts about things that happened within the domain.
They are immutable records of state transitions that other parts of the system
can react to asynchronously (e.g., sending welcome emails, provisioning resources,
audit logging).

Events are collected by the aggregate and published after the operation succeeds.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class DomainEvent:
    """Base class for all domain events.

    Attributes:
        occurred_at: When the event happened (UTC).
    """

    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class OrganizationCreated(DomainEvent):
    """An Organization was created."""

    organization_id: str
    name: str
    slug: str
    plan: str


@dataclass(frozen=True, slots=True)
class OrganizationRenamed(DomainEvent):
    """An Organization's display name was changed."""

    organization_id: str
    old_name: str
    new_name: str


@dataclass(frozen=True, slots=True)
class OrganizationActivated(DomainEvent):
    """An Organization was activated."""

    organization_id: str


@dataclass(frozen=True, slots=True)
class OrganizationDeactivated(DomainEvent):
    """An Organization was deactivated."""

    organization_id: str


@dataclass(frozen=True, slots=True)
class OrganizationSuspended(DomainEvent):
    """An Organization was suspended due to policy violation or billing."""

    organization_id: str
    reason: str


@dataclass(frozen=True, slots=True)
class OrganizationPlanChanged(DomainEvent):
    """An Organization's subscription plan was changed."""

    organization_id: str
    old_plan: str
    new_plan: str


def _now() -> datetime:
    """Internal helper for event timestamp generation."""
    return utc_now()
