"""IAlertProvider — the Alert Engine's one inbound port for loading an
existing `Alert` by dedup key (M44C §2's "Load Alert aggregate").

No persistence, no repository implementation lives in this milestone —
`AlertApplicationService` never queries a database itself; it asks this
port whether an alert with the same dedup key already exists so it can
decide deduplication (M44C §6), reusing `Alert.deduplicate()` rather
than reimplementing what "duplicate" means.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from redforge.shared.identifiers import EntityId
    from siem_alerting.domain.aggregates.alert import Alert


class IAlertProvider(Protocol):
    def find_by_dedup_key(self, tenant_id: EntityId, dedup_key: str) -> Alert | None:
        """The most recent alert for `tenant_id` sharing `dedup_key`, if
        any — regardless of its current lifecycle status.
        `AlertApplicationService` decides what to do with a `CLOSED`
        one (M44C §7's "closed alerts" validation): a closed alert is
        never deduplicated against, only an open one."""
        ...
