from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from regulatory_notification.domain.aggregates.notification_draft import NotificationDraft
    from regulatory_notification.domain.aggregates.regulatory_notification import (
        RegulatoryNotification,
    )
    from regulatory_notification.domain.value_objects.enums import RegulatoryRegime
    from regulatory_notification.domain.value_objects.identifiers import RegNotificationId, TenantId


class IRegulatoryNotificationRepository(ABC):
    @abstractmethod
    async def find_by_id(
        self, tenant_id: TenantId, notification_id: RegNotificationId
    ) -> RegulatoryNotification | None: ...
    @abstractmethod
    async def find_by_incident(
        self, tenant_id: TenantId, incident_id: str
    ) -> list[RegulatoryNotification]: ...
    @abstractmethod
    async def find_by_regime(
        self, tenant_id: TenantId, incident_id: str, regime: RegulatoryRegime
    ) -> RegulatoryNotification | None: ...
    @abstractmethod
    async def find_active_for_alerting(self, now: datetime) -> list[RegulatoryNotification]: ...
    @abstractmethod
    async def save(self, tenant_id: TenantId, notification: RegulatoryNotification) -> None: ...


class INotificationDraftRepository(ABC):
    @abstractmethod
    async def find_current_draft(
        self, tenant_id: TenantId, notification_id: RegNotificationId
    ) -> NotificationDraft | None: ...
    @abstractmethod
    async def find_all_drafts(
        self, tenant_id: TenantId, notification_id: RegNotificationId
    ) -> list[NotificationDraft]: ...
    @abstractmethod
    async def save(self, tenant_id: TenantId, draft: NotificationDraft) -> None: ...


class INotificationDeadlineRepository(ABC):
    @abstractmethod
    async def find_active_deadlines(
        self, *, before_deadline: datetime | None = None
    ) -> list[dict[str, object]]: ...
    @abstractmethod
    async def find_by_notification(
        self, tenant_id: TenantId, notification_id: RegNotificationId
    ) -> list[dict[str, object]]: ...
    @abstractmethod
    async def mark_alert_sent(
        self, deadline_id: str, threshold_hours: int, sent_at: datetime
    ) -> None: ...
    @abstractmethod
    async def record_breach(self, deadline_id: str, detected_at: datetime) -> None: ...
    @abstractmethod
    async def cancel_deadline(self, deadline_id: str) -> None: ...
    @abstractmethod
    async def upsert(self, row: dict[str, object]) -> None: ...
