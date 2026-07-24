"""NormalizedEventDraft — the mapping output of an `IEventNormalizer`.

A normalizer extracts *semantic* fields from a provider-native payload
(what CEM category, what happened, when, to/by whom) but does not
construct the `CanonicalEvent` itself — that stays the exclusive job of
`CanonicalEventFactory` (M43B), keeping "one sanctioned construction
path" true even for normalized events, not only ingested ones (M43C's
own rule, carried forward here).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping
    from datetime import datetime

    from siem_shared.domain.value_objects.entity_ref import EntityRef
    from siem_shared.domain.value_objects.event_category import EventCategory
    from siem_shared.domain.value_objects.event_outcome import EventOutcome
    from siem_shared.domain.value_objects.event_severity import EventSeverity


@dataclass(frozen=True, slots=True)
class NormalizedEventDraft:
    category: EventCategory
    outcome: EventOutcome
    occurred_at: datetime
    severity: EventSeverity | None = None
    actor: EntityRef | None = None
    target: EntityRef | None = None
    attributes: Mapping[str, object] = field(default_factory=dict)
    raw_payload_ref: str | None = None
