"""Email delivery adapter — Phase 4 (in-process, no external SMTP)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from reporting.domain.ports.i_report_delivery_port import IReportDeliveryPort
from reporting.domain.value_objects.enums import DeliveryChannel, DeliveryStatus
from reporting.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:
    from uuid import UUID

    from reporting.infrastructure.persistence.delivery_audit_store import (
        DeliveryAuditStore,
    )


class EmailReportDeliveryAdapter(IReportDeliveryPort):
    def __init__(self, audit: DeliveryAuditStore) -> None:
        self._audit = audit
        self.sent: list[dict[str, object]] = []

    async def deliver(
        self,
        tenant_id: TenantId,
        instance_id: UUID,
        recipients: list[str],
        artifact_ref: str,
    ) -> int:
        if not recipients:
            self._audit.append(
                tenant_id=tenant_id,
                instance_id=instance_id,
                channel=DeliveryChannel.EMAIL.value,
                recipients=[],
                status=DeliveryStatus.SKIPPED.value,
                artifact_ref=artifact_ref,
            )
            return 0
        self.sent.append(
            {
                "tenant_id": str(tenant_id),
                "instance_id": str(instance_id),
                "recipients": list(recipients),
                "artifact_ref": artifact_ref,
                "channel": "email",
            }
        )
        self._audit.append(
            tenant_id=tenant_id,
            instance_id=instance_id,
            channel=DeliveryChannel.EMAIL.value,
            recipients=recipients,
            status=DeliveryStatus.SUCCEEDED.value,
            artifact_ref=artifact_ref,
        )
        return len(recipients)
