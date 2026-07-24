"""IEventStorageWriter — the Storage Foundation's one outbound port.

`StorageApplicationService` never persists anything itself (M43E §2);
handing a produced `StoragePlan` (and the event it plans for) to
whatever implements this port is the last thing it does. No
implementation lives in this milestone — any physical persistence
technology is explicitly out of scope and belongs to a future
infrastructure milestone.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from siem_shared.domain.value_objects.canonical_event import CanonicalEvent
    from siem_storage.application.dtos.storage_plan import StoragePlan


class IEventStorageWriter(Protocol):
    def write(self, event: CanonicalEvent, plan: StoragePlan) -> None: ...
