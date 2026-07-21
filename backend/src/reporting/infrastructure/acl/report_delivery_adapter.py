"""IReportDeliveryPort noop stub — Phase 2 (delivery deferred to Phase 4)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from reporting.domain.ports.i_report_delivery_port import IReportDeliveryPort

if TYPE_CHECKING:
    from uuid import UUID


class NoopReportDeliveryAdapter(IReportDeliveryPort):
    async def deliver(
        self,
        tenant_id: UUID,
        instance_id: UUID,
        recipients: list[str],
        artifact_ref: str,
    ) -> int:
        del tenant_id, instance_id, artifact_ref, recipients
        return 0
