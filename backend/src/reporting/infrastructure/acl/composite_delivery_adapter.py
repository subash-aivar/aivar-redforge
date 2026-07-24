"""Routes delivery by channel hint in recipients or default email."""

from __future__ import annotations

from typing import TYPE_CHECKING

from reporting.domain.ports.i_report_delivery_port import IReportDeliveryPort
from reporting.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:
    from uuid import UUID

    from reporting.infrastructure.acl.email_delivery_adapter import (
        EmailReportDeliveryAdapter,
    )
    from reporting.infrastructure.acl.webhook_delivery_adapter import (
        WebhookReportDeliveryAdapter,
    )


class CompositeReportDeliveryAdapter(IReportDeliveryPort):
    def __init__(
        self,
        email: EmailReportDeliveryAdapter,
        webhook: WebhookReportDeliveryAdapter,
        *,
        default_channel: str = "email",
    ) -> None:
        self.email = email
        self.webhook = webhook
        self.default_channel = default_channel

    async def deliver(
        self,
        tenant_id: TenantId,
        instance_id: UUID,
        recipients: list[str],
        artifact_ref: str,
    ) -> int:
        webhook_urls = [
            r for r in recipients if r.startswith("http://") or r.startswith("https://")
        ]
        emails = [r for r in recipients if r not in webhook_urls]
        total = 0
        if webhook_urls:
            total += await self.webhook.deliver(tenant_id, instance_id, webhook_urls, artifact_ref)
        if emails or (not recipients and self.default_channel == "email"):
            total += await self.email.deliver(tenant_id, instance_id, emails, artifact_ref)
        return total
