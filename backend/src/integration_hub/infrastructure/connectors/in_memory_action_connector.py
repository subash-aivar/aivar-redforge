from __future__ import annotations

from datetime import UTC, datetime

from integration_hub.domain.value_objects.enums import ConnectorFailureMode, ConnectorHealthStatus
from integration_hub.domain.value_objects.results import ConnectorActionResult


class InMemoryActionConnector:
    def __init__(self, *, fail_mode: ConnectorFailureMode | None = None) -> None:
        self.fail_mode = fail_mode
        self.executions: list[dict[str, object]] = []
        self.verify_results: dict[str, ConnectorActionResult] = {}

    async def execute(
        self, action_type: str, parameters: dict[str, object], tenant_id: str
    ) -> ConnectorActionResult:
        now = datetime.now(UTC)
        self.executions.append(
            {"action_type": action_type, "parameters": parameters, "tenant_id": tenant_id}
        )
        if self.fail_mode is not None:
            return ConnectorActionResult(
                False,
                self.fail_mode,
                None,
                {"error": self.fail_mode.value},
                now,
                5,
                False,
                {},
            )
        ref = f"ext-{len(self.executions)}"
        return ConnectorActionResult(
            True, None, ref, {"ok": True}, now, 5, True, {"undo": action_type}
        )

    async def rollback(
        self, original_action_id: str, parameters: dict[str, object], tenant_id: str
    ) -> ConnectorActionResult:
        del parameters, tenant_id
        now = datetime.now(UTC)
        return ConnectorActionResult(
            True, None, f"rb-{original_action_id}", {"rolled_back": True}, now, 3, False, {}
        )

    async def health_check(self, tenant_id: str) -> ConnectorHealthStatus:
        del tenant_id
        if self.fail_mode in {
            ConnectorFailureMode.NETWORK_FAILURE,
            ConnectorFailureMode.AUTH_FAILURE,
        }:
            return ConnectorHealthStatus.UNHEALTHY
        return ConnectorHealthStatus.HEALTHY

    async def verify_outcome(
        self, execution_id: str, step_number: int, tenant_id: str
    ) -> ConnectorActionResult | None:
        del tenant_id
        return self.verify_results.get(f"{execution_id}:{step_number}")
