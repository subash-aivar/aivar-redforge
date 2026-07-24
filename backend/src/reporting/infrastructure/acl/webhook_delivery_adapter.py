"""Webhook delivery adapter — Phase 4 (records payloads; no outbound HTTP in tests)."""

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


class WebhookReportDeliveryAdapter(IReportDeliveryPort):
    def __init__(self, audit: DeliveryAuditStore) -> None:
        self._audit = audit
        self.webhooks: list[dict[str, object]] = []

    async def deliver(
        self,
        tenant_id: TenantId,
        instance_id: UUID,
        recipients: list[str],
        artifact_ref: str,
    ) -> int:
        # recipients interpreted as webhook URLs
        if not recipients:
            self._audit.append(
                tenant_id=tenant_id,
                instance_id=instance_id,
                channel=DeliveryChannel.WEBHOOK.value,
                recipients=[],
                status=DeliveryStatus.SKIPPED.value,
                artifact_ref=artifact_ref,
            )
            return 0
        for url in recipients:
            self.webhooks.append(
                {
                    "url": url,
                    "tenant_id": str(tenant_id),
                    "instance_id": str(instance_id),
                    "artifact_ref": artifact_ref,
                }
            )
        self._audit.append(
            tenant_id=tenant_id,
            instance_id=instance_id,
            channel=DeliveryChannel.WEBHOOK.value,
            recipients=recipients,
            status=DeliveryStatus.SUCCEEDED.value,
            artifact_ref=artifact_ref,
        )
        return len(recipients)
