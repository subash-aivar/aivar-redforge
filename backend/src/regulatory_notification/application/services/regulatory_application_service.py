from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from regulatory_notification.application._auth import require_officer, require_submit_role
from regulatory_notification.application.exceptions import ApplicationNotFoundError
from regulatory_notification.domain.aggregates.notification_draft import NotificationDraft
from regulatory_notification.domain.aggregates.regulatory_notification import RegulatoryNotification
from regulatory_notification.domain.services.deadline_alerting_service import (
    DeadlineAlertingService,
)
from regulatory_notification.domain.services.deadline_computation_service import (
    RegulatoryDeadlineComputationService,
)
from regulatory_notification.domain.services.jurisdiction_mapping_service import (
    JurisdictionMappingService,
)
from regulatory_notification.domain.services.regulatory_submission_service import (
    RegulatorySubmissionService,
)
from regulatory_notification.domain.value_objects.enums import RegulatoryRegime
from regulatory_notification.domain.value_objects.identifiers import (
    DraftId,
    RegNotificationId,
    TenantId,
)


class RegulatoryApplicationService:
    def __init__(self, notifications: Any, drafts: Any, deadlines: Any, alert_port: Any) -> None:
        self._notifications = notifications
        self._drafts = drafts
        self._deadlines = deadlines
        self._alert_port = alert_port
        self._compute = RegulatoryDeadlineComputationService()
        self._juris = JurisdictionMappingService()
        self._alerting = DeadlineAlertingService()
        self._submission = RegulatorySubmissionService()
        self.jurisdiction_config: dict[str, set[str]] = {}
        self.events: list[Any] = []

    async def configure_jurisdictions(
        self, tenant_id: TenantId, jurisdictions: set[str], roles: tuple[str, ...]
    ) -> dict[str, Any]:
        if "incident:ciso" not in roles:
            from regulatory_notification.application.exceptions import ApplicationForbiddenError

            raise ApplicationForbiddenError("incident:ciso")
        self.jurisdiction_config[str(tenant_id)] = set(jurisdictions)
        return {"jurisdictions": sorted(jurisdictions)}

    async def start_clocks(
        self,
        tenant_id: TenantId,
        incident_id: str,
        regimes: list[str] | None,
        roles: tuple[str, ...],
        classified_at: datetime | None = None,
    ) -> list[dict[str, Any]]:
        if (
            "incident:ciso" not in roles
            and "regulatory:legal" not in roles
            and "system" not in roles
        ):
            require_officer(roles)
        tenant = tenant_id
        now = classified_at or datetime.now(UTC)
        if regimes:
            regime_list = [RegulatoryRegime(r) for r in regimes]
        else:
            js = self.jurisdiction_config.get(str(tenant_id), {"EU", "US"})
            regime_list = self._juris.regimes_for(js)
        created = []
        for regime in regime_list:
            existing = await self._notifications.find_by_regime(tenant, incident_id, regime)
            if existing:
                continue
            deadline = self._compute.compute(regime, now)
            n = RegulatoryNotification.start_clock(
                RegNotificationId.generate(),
                tenant,
                incident_id,
                regime,
                ",".join(sorted(self.jurisdiction_config.get(str(tenant_id), set()))),
                deadline,
            )
            await self._notifications.save(tenant, n)
            self.events.extend(n.pop_events())
            await self._deadlines.upsert(
                {
                    "deadline_id": str(n.notification_id),
                    "tenant_id": str(tenant),
                    "notification_id": str(n.notification_id),
                    "regime": regime.value,
                    "deadline_at": deadline.deadline_at,
                    "deadline_hours": deadline.deadline_hours,
                    "clock_started_at": deadline.clock_started_at,
                    "cancelled": False,
                }
            )
            created.append(
                {
                    "notification_id": str(n.notification_id),
                    "regime": regime.value,
                    "deadline_at": deadline.deadline_at.isoformat(),
                }
            )
        return created

    async def create_draft(
        self,
        tenant_id: TenantId,
        notification_id: UUID,
        content: str,
        actor: str,
        roles: tuple[str, ...],
    ) -> dict[str, Any]:
        require_officer(roles)
        tenant = tenant_id
        n = await self._notifications.find_by_id(tenant, RegNotificationId(notification_id))
        if n is None:
            raise ApplicationNotFoundError("notification")
        draft = NotificationDraft.create(
            DraftId.generate(),
            tenant,
            RegNotificationId(notification_id),
            content,
            actor,
            datetime.now(UTC),
        )
        await self._drafts.save(tenant, draft)
        n.mark_draft_in_progress(tenant, str(draft.draft_id))
        await self._notifications.save(tenant, n)
        return {"draft_id": str(draft.draft_id), "version": draft.version_number}

    async def revise_draft(
        self,
        tenant_id: TenantId,
        notification_id: UUID,
        content: str,
        actor: str,
        roles: tuple[str, ...],
    ) -> dict[str, Any]:
        require_officer(roles)
        tenant = tenant_id
        current = await self._drafts.find_current_draft(tenant, RegNotificationId(notification_id))
        if current is None:
            raise ApplicationNotFoundError("draft")
        revised = current.revise(tenant, content, actor, datetime.now(UTC))
        await self._drafts.save(tenant, revised)
        return {"draft_id": str(revised.draft_id), "version": revised.version_number}

    async def finalize_draft(
        self, tenant_id: TenantId, notification_id: UUID, actor: str, roles: tuple[str, ...]
    ) -> dict[str, Any]:
        require_submit_role(roles)  # legal finalizes
        tenant = tenant_id
        draft = await self._drafts.find_current_draft(tenant, RegNotificationId(notification_id))
        if draft is None:
            raise ApplicationNotFoundError("draft")
        draft.finalize(tenant, actor, datetime.now(UTC))
        await self._drafts.save(tenant, draft)
        self.events.extend(draft.pop_events())
        n = await self._notifications.find_by_id(tenant, RegNotificationId(notification_id))
        if n is None:
            raise ApplicationNotFoundError("notification")
        if n.status.value == "CLOCK_STARTED":
            n.mark_draft_in_progress(tenant, str(draft.draft_id))
        n.mark_ready(tenant)
        await self._notifications.save(tenant, n)
        return {"status": n.status.value}

    async def submit(
        self,
        tenant_id: TenantId,
        notification_id: UUID,
        actor: str,
        method: str,
        reference: str,
        roles: tuple[str, ...],
    ) -> dict[str, Any]:
        require_submit_role(roles)
        self._submission.ensure_human_command("SubmitRegulatoryNotification")
        tenant = tenant_id
        n = await self._notifications.find_by_id(tenant, RegNotificationId(notification_id))
        if n is None:
            raise ApplicationNotFoundError("notification")
        n.submit(tenant, actor, method, reference, datetime.now(UTC))
        await self._notifications.save(tenant, n)
        self.events.extend(n.pop_events())
        await self._deadlines.cancel_deadline(str(notification_id))
        return {"status": n.status.value, "reference": reference}

    async def acknowledge(
        self, tenant_id: TenantId, notification_id: UUID, actor: str, roles: tuple[str, ...]
    ) -> dict[str, Any]:
        require_submit_role(roles)
        tenant = tenant_id
        n = await self._notifications.find_by_id(tenant, RegNotificationId(notification_id))
        if n is None:
            raise ApplicationNotFoundError("notification")
        n.acknowledge(tenant, actor, datetime.now(UTC))
        await self._notifications.save(tenant, n)
        self.events.extend(n.pop_events())
        return {"status": n.status.value}

    async def list_for_incident(
        self, tenant_id: TenantId, incident_id: str
    ) -> list[dict[str, Any]]:
        tenant = tenant_id
        rows = await self._notifications.find_by_incident(tenant, incident_id)
        return [
            {
                "notification_id": str(n.notification_id),
                "regime": n.regime.value,
                "status": n.status.value,
                "deadline_at": n.deadline.deadline_at.isoformat(),
                "deadline_hours": n.deadline.deadline_hours,
                "advisory": n.deadline.advisory,
                "submitted": n.submission_record is not None,
            }
            for n in rows
        ]

    async def deadline_dashboard(self, tenant_id: TenantId) -> list[dict[str, Any]]:
        now = datetime.now(UTC)
        active = await self._notifications.find_active_for_alerting(now)
        return [
            {
                "notification_id": str(n.notification_id),
                "tenant_id": str(n.tenant_id),
                "regime": n.regime.value,
                "deadline_at": n.deadline.deadline_at.isoformat(),
                "status": self._alerting.status_for(n.deadline.deadline_at, now).value,
                "hours_remaining": (n.deadline.deadline_at - now).total_seconds() / 3600.0,
            }
            for n in active
            if str(n.tenant_id) == str(tenant_id)
        ]
