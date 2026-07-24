from __future__ import annotations

from typing import Any
from uuid import UUID

from integration_hub.application.commands.connector_commands import TriggerHealthCheck
from integration_hub.domain.value_objects.identifiers import TenantId


class ConnectorHealthWorker:
    def __init__(self, app: Any) -> None:
        self._app = app
        self.ticks = 0

    async def tick(
        self, tenant_id: TenantId, roles: tuple[str, ...] = ("integration:admin",)
    ) -> int:
        self.ticks += 1
        regs = await self._app.list_connectors(tenant_id, roles)
        checked = 0
        for reg in regs:
            if reg.status == "DISABLED":
                continue
            await self._app.health_check(
                TriggerHealthCheck(tenant_id, UUID(reg.connector_id), roles)
            )
            checked += 1
        return checked


class HealthScheduler:
    def __init__(self, worker: ConnectorHealthWorker) -> None:
        self.worker = worker

    async def tick(self, tenant_id: TenantId) -> int:
        return await self.worker.tick(tenant_id)
