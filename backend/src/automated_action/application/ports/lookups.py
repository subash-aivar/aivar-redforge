from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class PlaybookStepView:
    step_number: int
    action_type: str
    connector_type: str
    target_selector: str
    parameters: dict[str, object]
    impact_level: str


@dataclass(frozen=True, slots=True)
class PlaybookLookupView:
    playbook_id: str
    version_number: int
    content_hash: str
    max_impact_level: str
    status: str
    steps: list[PlaybookStepView]


@dataclass(frozen=True, slots=True)
class PolicyLookupView:
    kill_switch_triggered: bool
    max_concurrent_executions: int
    max_actions_per_hour: int


class IPlaybookLookupPort(Protocol):
    async def get_approved_version(
        self, tenant_id: str, playbook_id: str, version_number: int
    ) -> PlaybookLookupView | None: ...

    async def get_policy(self, tenant_id: str) -> PolicyLookupView: ...


@dataclass(frozen=True, slots=True)
class ConnectorExecResult:
    success: bool
    failure_mode: str | None
    external_reference: str | None
    duration_ms: int
    rollback_available: bool
    rollback_parameters_ref: str | None


class IConnectorExecutionPort(Protocol):
    async def execute(
        self,
        tenant_id: str,
        connector_type: str,
        action_type: str,
        parameters: dict[str, object],
        idempotency_key: str,
    ) -> ConnectorExecResult: ...

    async def verify_outcome(
        self, tenant_id: str, connector_type: str, execution_id: str, step_number: int
    ) -> ConnectorExecResult | None: ...

    async def rollback(
        self, tenant_id: str, connector_type: str, original_action_id: str
    ) -> ConnectorExecResult: ...
