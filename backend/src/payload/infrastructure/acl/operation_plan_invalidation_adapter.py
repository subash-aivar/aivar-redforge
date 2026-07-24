"""Plan invalidation ACL adapters."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from payload.domain.ports.i_plan_invalidation_port import IPlanInvalidationPort
from payload.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:
    from collections.abc import Callable

    from operation.application.services.operation_application_service import (
        OperationApplicationService,
    )


class DegradedPlanInvalidationAdapter(IPlanInvalidationPort):
    """Records invalidation calls; does not touch operation plans."""

    def __init__(self) -> None:
        self.calls: list[tuple[UUID, UUID]] = []

    async def invalidate_plans_for_payload(
        self, tenant_id: TenantId, payload_id: UUID
    ) -> int:
        self.calls.append((tenant_id, payload_id))
        return 0


class OperationPlanInvalidationAdapter(IPlanInvalidationPort):
    """Real adapter — delegates to OperationApplicationService."""

    def __init__(
        self,
        operation_service_factory: Callable[[], OperationApplicationService],
    ) -> None:
        self._operation_service_factory = operation_service_factory

    async def invalidate_plans_for_payload(
        self, tenant_id: TenantId, payload_id: UUID
    ) -> int:
        svc = self._operation_service_factory()
        return await svc.invalidate_plans_referencing_payload(
            tenant_id=tenant_id,
            payload_id=payload_id,
        )
