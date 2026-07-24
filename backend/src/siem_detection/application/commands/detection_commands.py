"""CQRS commands for siem_detection's Detection Engine (M42 Phase 6).
Each event is evaluated independently against every active rule the
tenant has — no correlation, no windowing, no cross-event state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redforge.shared.identifiers import EntityId
    from siem_shared.domain.value_objects.canonical_event import CanonicalEvent


@dataclass(frozen=True, slots=True)
class EvaluateCanonicalEventCommand:
    tenant_id: EntityId
    canonical_event: CanonicalEvent
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EvaluateBatchCommand:
    tenant_id: EntityId
    events: tuple[CanonicalEvent, ...] = field(default_factory=tuple)
    actor_roles: tuple[str, ...] = ()
