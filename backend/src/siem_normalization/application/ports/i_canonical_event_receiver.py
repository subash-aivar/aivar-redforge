"""ICanonicalEventReceiver — siem_normalization's own outbound port.

Structurally identical to `siem_ingestion`'s port of the same name, but
deliberately a distinct type: bounded contexts do not share
application-layer ports even when the shape coincides, because each
represents a different actual downstream dependency (this context's
receiver is `siem_storage`'s eventual hot-tier write path, M42 Phase 5
— not the same relationship `siem_ingestion`'s port represents).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from siem_shared.domain.value_objects.canonical_event import CanonicalEvent


class ICanonicalEventReceiver(Protocol):
    def receive(self, event: CanonicalEvent) -> None: ...
