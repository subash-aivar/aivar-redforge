"""Base domain event for campaign_intel. No event bus implemented in
this milestone — pure value objects an aggregate appends to its pending-
events list; mirrors `malware_intel.domain.events.base.BaseDomainEvent`
exactly."""

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
