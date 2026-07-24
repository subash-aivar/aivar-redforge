"""IInvestigationProvider — the Investigation Engine's one inbound port
for loading an in-flight `InvestigationTimeline` (M44D §2's "Load
InvestigationTimeline").

No persistence, no repository implementation lives in this milestone.
`find_open_timeline` returns only a currently-*open* investigation for
the given scope — a closed one is never returned, exactly mirroring
M44C's identical "a closed Alert is never deduplicated against" pattern
for Alert dedup. `InvestigationApplicationService` never queries a
database itself.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from redforge.shared.identifiers import EntityId
    from siem_investigation.domain.aggregates.investigation_timeline import InvestigationTimeline
    from siem_investigation.domain.value_objects.enums import TimelineScopeType


class IInvestigationProvider(Protocol):
    def find_open_timeline(
        self, tenant_id: EntityId, scope_type: TimelineScopeType, scope_ref: str
    ) -> InvestigationTimeline | None: ...
