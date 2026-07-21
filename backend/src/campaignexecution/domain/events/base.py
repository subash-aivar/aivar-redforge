"""BaseDomainEvent for the campaignexecution context."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class BaseDomainEvent:
    event_id: str
    occurred_at: datetime
    tenant_id: str
    aggregate_id: str
    aggregate_type: str
