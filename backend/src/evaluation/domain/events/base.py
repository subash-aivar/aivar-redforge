"""Base domain event for the evaluation context."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from evaluation.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True, kw_only=True)
class BaseDomainEvent:
    event_id: str
    occurred_at: datetime
    tenant_id: TenantId
    aggregate_id: str
    aggregate_type: str
    event_version: int = 1
