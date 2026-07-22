from __future__ import annotations

from typing import Protocol

from integration_hub.domain.value_objects.enums import ConnectorHealthStatus
from integration_hub.domain.value_objects.results import ConnectorActionResult


class IActionConnector(Protocol):
    async def execute(
        self, action_type: str, parameters: dict[str, object], tenant_id: str
    ) -> ConnectorActionResult: ...

    async def rollback(
        self, original_action_id: str, parameters: dict[str, object], tenant_id: str
    ) -> ConnectorActionResult: ...

    async def health_check(self, tenant_id: str) -> ConnectorHealthStatus: ...

    async def verify_outcome(
        self, execution_id: str, step_number: int, tenant_id: str
    ) -> ConnectorActionResult | None: ...
