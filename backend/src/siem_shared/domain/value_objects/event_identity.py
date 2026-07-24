"""EventIdentity — a CanonicalEvent's platform identifier plus its
idempotency fingerprint (M37 §2.1)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redforge.shared.identifiers import EntityId
    from siem_shared.domain.value_objects.event_fingerprint import EventFingerprint


@dataclass(frozen=True, slots=True)
class EventIdentity:
    event_id: EntityId
    fingerprint: EventFingerprint
