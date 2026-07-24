"""InvestigationTimeline — ordered, cross-source event sequence for a
given entity/alert/incident scope (M37 §2.2, §7).

Predominantly a *read-model* (M37 §2.2): in later phases this is
composed by querying stored events, not by accumulating domain events
of its own. This Phase 1 shape gives it a constructible, unit-testable
domain form — insertion in occurred_at order, no duplicate entries per
event_id — ahead of the query-composition machinery built in M42
Phase 9.
"""

from __future__ import annotations

import bisect
from typing import TYPE_CHECKING

from siem_investigation.domain.exceptions.domain_exceptions import (
    DuplicateTimelineEntryError,
    EmptyScopeRefError,
    TenantMismatch,
)

if TYPE_CHECKING:
    from siem_investigation.domain.value_objects.enums import TimelineScopeType
    from siem_investigation.domain.value_objects.identifiers import (
        InvestigationTimelineId,
        TenantId,
    )
    from siem_investigation.domain.value_objects.timeline_entry import TimelineEntry


class InvestigationTimeline:
    __slots__ = (
        "_entry_event_ids",
        "entries",
        "scope_ref",
        "scope_type",
        "tenant_id",
        "timeline_id",
    )

    def __init__(
        self,
        timeline_id: InvestigationTimelineId,
        tenant_id: TenantId,
        scope_type: TimelineScopeType,
        scope_ref: str,
        entries: list[TimelineEntry] | None = None,
    ) -> None:
        self.timeline_id = timeline_id
        self.tenant_id = tenant_id
        self.scope_type = scope_type
        self.scope_ref = scope_ref
        self.entries = list(entries or [])
        self._entry_event_ids = {e.event_id for e in self.entries}

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    @classmethod
    def create(
        cls,
        timeline_id: InvestigationTimelineId,
        tenant_id: TenantId,
        scope_type: TimelineScopeType,
        scope_ref: str,
    ) -> InvestigationTimeline:
        if not scope_ref.strip():
            raise EmptyScopeRefError()
        return cls(
            timeline_id=timeline_id,
            tenant_id=tenant_id,
            scope_type=scope_type,
            scope_ref=scope_ref.strip(),
        )

    def add_entry(self, tenant_id: TenantId, entry: TimelineEntry) -> None:
        """Insert `entry` in `occurred_at` order — the timeline is always
        chronologically ordered, regardless of insertion order, and
        never contains two entries for the same source event."""
        self._assert_tenant(tenant_id)
        if entry.event_id in self._entry_event_ids:
            raise DuplicateTimelineEntryError(entry.event_id)
        occurred_at_values = [e.occurred_at for e in self.entries]
        index = bisect.bisect_right(occurred_at_values, entry.occurred_at)
        self.entries.insert(index, entry)
        self._entry_event_ids.add(entry.event_id)
