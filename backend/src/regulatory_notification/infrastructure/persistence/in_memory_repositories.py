"""In-memory regulatory repositories."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from regulatory_notification.domain.aggregates.notification_draft import NotificationDraft
from regulatory_notification.domain.aggregates.regulatory_notification import (
    RegulatoryNotification,
)
from regulatory_notification.domain.repositories.i_repositories import (
    INotificationDeadlineRepository,
    INotificationDraftRepository,
    IRegulatoryNotificationRepository,
)
from regulatory_notification.domain.value_objects.enums import (
    NotificationStatus,
    RegulatoryRegime,
)
from regulatory_notification.domain.value_objects.identifiers import (
    RegNotificationId,
    TenantId,
)


class InMemoryRegulatoryNotificationRepository(IRegulatoryNotificationRepository):
    def __init__(self) -> None:
        self._items: dict[str, dict[str, RegulatoryNotification]] = {}

    async def find_by_id(
        self, tenant_id: TenantId, notification_id: RegNotificationId
    ) -> RegulatoryNotification | None:
        return self._items.get(str(tenant_id), {}).get(str(notification_id))

    async def find_by_incident(
        self, tenant_id: TenantId, incident_id: str
    ) -> list[RegulatoryNotification]:
        return [
            n for n in self._items.get(str(tenant_id), {}).values() if n.incident_id == incident_id
        ]

    async def find_by_regime(
        self, tenant_id: TenantId, incident_id: str, regime: RegulatoryRegime
    ) -> RegulatoryNotification | None:
        for n in await self.find_by_incident(tenant_id, incident_id):
            if n.regime == regime:
                return n
        return None

    async def find_active_for_alerting(self, now: datetime) -> list[RegulatoryNotification]:
        del now
        out: list[RegulatoryNotification] = []
        for tenant_map in self._items.values():
            for n in tenant_map.values():
                if n.status not in {
                    NotificationStatus.SUBMITTED,
                    NotificationStatus.ACKNOWLEDGED,
                }:
                    out.append(n)
        return out

    async def save(self, tenant_id: TenantId, notification: RegulatoryNotification) -> None:
        self._items.setdefault(str(tenant_id), {})[str(notification.notification_id)] = notification


class InMemoryNotificationDraftRepository(INotificationDraftRepository):
    def __init__(self) -> None:
        self._items: dict[str, list[NotificationDraft]] = {}

    def _key(self, tenant_id: TenantId, notification_id: RegNotificationId) -> str:
        return f"{tenant_id}:{notification_id}"

    async def find_current_draft(
        self, tenant_id: TenantId, notification_id: RegNotificationId
    ) -> NotificationDraft | None:
        rows = self._items.get(self._key(tenant_id, notification_id), [])
        return rows[-1] if rows else None

    async def find_all_drafts(
        self, tenant_id: TenantId, notification_id: RegNotificationId
    ) -> list[NotificationDraft]:
        return list(self._items.get(self._key(tenant_id, notification_id), []))

    async def save(self, tenant_id: TenantId, draft: NotificationDraft) -> None:
        self._items.setdefault(self._key(tenant_id, draft.notification_id), []).append(draft)


class InMemoryNotificationDeadlineRepository(INotificationDeadlineRepository):
    def __init__(self) -> None:
        self._rows: dict[str, dict[str, Any]] = {}
        self._alerts: list[dict[str, Any]] = []

    async def find_active_deadlines(
        self, *, before_deadline: datetime | None = None
    ) -> list[dict[str, Any]]:
        rows = list(self._rows.values())
        if before_deadline is not None:
            rows = [
                r for r in rows if r["deadline_at"] <= before_deadline and not r.get("cancelled")
            ]
        return rows

    async def find_by_notification(
        self, tenant_id: TenantId, notification_id: RegNotificationId
    ) -> list[dict[str, Any]]:
        return [
            r
            for r in self._rows.values()
            if r["tenant_id"] == str(tenant_id) and r["notification_id"] == str(notification_id)
        ]

    async def mark_alert_sent(
        self, deadline_id: str, threshold_hours: int, sent_at: datetime
    ) -> None:
        self._alerts.append(
            {"deadline_id": deadline_id, "threshold": threshold_hours, "sent_at": sent_at}
        )

    async def record_breach(self, deadline_id: str, detected_at: datetime) -> None:
        row = self._rows.get(deadline_id)
        if row is not None:
            row["breached_at"] = detected_at

    async def cancel_deadline(self, deadline_id: str) -> None:
        if deadline_id in self._rows:
            self._rows[deadline_id]["cancelled"] = True

    async def upsert(self, row: dict[str, Any]) -> None:
        self._rows[str(row["deadline_id"])] = row
