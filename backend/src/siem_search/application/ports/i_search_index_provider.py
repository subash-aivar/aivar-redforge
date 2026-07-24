"""ISearchIndexProvider — the tier-aware index-selection seam (M37 §10:
"chosen automatically by the query's own time-range... a query
spanning only the last 24h never touches warm/cold").

Not wired into `SearchApplicationService` in this milestone — a future
concrete `ISearchProvider` implementation is expected to depend on this
port internally to pick which physical index/store a query's
`TimeRange` should hit, once a real search backend exists. Defined now,
per M44E §7, as an interface only — no implementation, no index/tier
resolution logic.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from siem_search.domain.value_objects.enums import SearchEntityType
    from siem_search.domain.value_objects.time_range import TimeRange


class ISearchIndexProvider(Protocol):
    def resolve_index(self, entity_type: SearchEntityType, time_range: TimeRange) -> str:
        """Return an opaque identifier for whichever physical index/
        store should serve `time_range` for `entity_type`."""
        ...
