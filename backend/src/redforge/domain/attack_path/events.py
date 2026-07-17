"""Domain events for the Attack Path Engine — M22 Phase 5."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class AttackPathComputed:
    path_id: str
    organization_id: str
    root_entity_id: str
    step_count: int
    path_confidence: str
    computed_at: datetime


@dataclass(frozen=True, slots=True)
class AttackPathUpdated:
    path_id: str
    organization_id: str
    from_status: str
    to_status: str
    updated_at: datetime


AttackPathDomainEvent = AttackPathComputed | AttackPathUpdated
