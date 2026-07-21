from __future__ import annotations

from datetime import datetime
from typing import Any

from regulatory_notification.domain.events.regulatory_events import RegulatoryNotificationApproved
from regulatory_notification.domain.exceptions.domain_exceptions import (
    InvalidNotificationTransition,
    TenantMismatch,
)
from regulatory_notification.domain.value_objects.enums import DraftStatus
from regulatory_notification.domain.value_objects.identifiers import (
    DraftId,
    RegNotificationId,
    TenantId,
)


class NotificationDraft:
    def __init__(
        self,
        draft_id: DraftId,
        tenant_id: TenantId,
        notification_id: RegNotificationId,
        version_number: int,
        content: str,
        authored_by: str,
        authored_at: datetime,
        status: DraftStatus,
        *,
        approved_by: str | None = None,
        approved_at: datetime | None = None,
    ) -> None:
        self.draft_id = draft_id
        self.tenant_id = tenant_id
        self.notification_id = notification_id
        self.version_number = version_number
        self.content = content
        self.authored_by = authored_by
        self.authored_at = authored_at
        self.status = status
        self.approved_by = approved_by
        self.approved_at = approved_at
        self._pending_events: list[Any] = []

    def pop_events(self) -> list[Any]:
        ev = list(self._pending_events)
        self._pending_events.clear()
        return ev

    @classmethod
    def create(
        cls,
        draft_id: DraftId,
        tenant_id: TenantId,
        notification_id: RegNotificationId,
        content: str,
        authored_by: str,
        at: datetime,
        version: int = 1,
    ) -> NotificationDraft:
        return cls(
            draft_id,
            tenant_id,
            notification_id,
            version,
            content,
            authored_by,
            at,
            DraftStatus.DRAFT,
        )

    def revise(
        self, tenant_id: TenantId, content: str, authored_by: str, at: datetime
    ) -> NotificationDraft:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch()
        return NotificationDraft(
            DraftId.generate(),
            tenant_id,
            self.notification_id,
            self.version_number + 1,
            content,
            authored_by,
            at,
            DraftStatus.REVISED,
        )

    def finalize(self, tenant_id: TenantId, approved_by: str, at: datetime) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch()
        if self.status == DraftStatus.FINAL:
            raise InvalidNotificationTransition("already final")
        self.status = DraftStatus.FINAL
        self.approved_by = approved_by
        self.approved_at = at
        self._pending_events.append(
            RegulatoryNotificationApproved(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.notification_id),
                notification_id=str(self.notification_id),
                approved_by=approved_by,
            )
        )
