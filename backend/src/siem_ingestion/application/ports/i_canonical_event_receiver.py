"""ICanonicalEventReceiver — the ingestion pipeline's one outbound port.

The pipeline's responsibility ends immediately after producing a
validated `CanonicalEvent` (M43C §objective) — handing it to whatever
implements this port is the last thing `IngestionApplicationService`
does with it. No implementation lives in this milestone: normalization
(M42 Phase 4) is the first real implementer, and this interface is
deliberately shaped so that milestone requires zero changes here to
plug in — the same "future connectors require zero redesign" principle
M37 §17 already commits the SIEM to.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from siem_shared.domain.value_objects.canonical_event import CanonicalEvent


class ICanonicalEventReceiver(Protocol):
    def receive(self, event: CanonicalEvent) -> None: ...
