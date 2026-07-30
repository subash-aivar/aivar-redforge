"""Base domain event for attack_surface_management. No event bus is
implemented in this milestone — these are pure value objects an
aggregate appends to its pending-events list; wiring a dispatcher is
deferred to a later phase."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import uuid4


@dataclass(frozen=True, slots=True)
class BaseDomainEvent:
    event_id: str = field(default_factory=lambda: str(uuid4()))
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    tenant_id: str = ""
    aggregate_id: str = ""
    aggregate_type: str = ""
