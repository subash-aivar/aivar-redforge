from __future__ import annotations

from automated_action.application.ports.lookups import (
    ConnectorExecResult,
    PlaybookLookupView,
    PolicyLookupView,
)


class InMemoryPlaybookLookup:
    def __init__(self) -> None:
        self.playbooks: dict[str, PlaybookLookupView] = {}
        self.policies: dict[str, PolicyLookupView] = {}

    def put(self, view: PlaybookLookupView) -> None:
        self.playbooks[f"{view.playbook_id}:{view.version_number}"] = view

    def put_policy(self, tenant_id: str, policy: PolicyLookupView) -> None:
        self.policies[tenant_id] = policy

    async def get_approved_version(
        self, tenant_id: str, playbook_id: str, version_number: int
    ) -> PlaybookLookupView | None:
        del tenant_id
        return self.playbooks.get(f"{playbook_id}:{version_number}")

    async def get_policy(self, tenant_id: str) -> PolicyLookupView:
        return self.policies.get(tenant_id, PolicyLookupView(False, 5, 100))


class InMemoryConnectorExecutionPort:
    def __init__(self) -> None:
        self.fail_next = False
        self.calls: list[str] = []

    async def execute(
        self,
        tenant_id: str,
        connector_type: str,
        action_type: str,
        parameters: dict[str, object],
        idempotency_key: str,
    ) -> ConnectorExecResult:
        del tenant_id, parameters
        self.calls.append(idempotency_key)
        if self.fail_next:
            self.fail_next = False
            return ConnectorExecResult(False, "SERVER_ERROR", None, 5, False, None)
        return ConnectorExecResult(
            True, None, f"ext-{len(self.calls)}", 5, True, f"rb:{connector_type}:{action_type}"
        )

    async def verify_outcome(
        self, tenant_id: str, connector_type: str, execution_id: str, step_number: int
    ) -> ConnectorExecResult | None:
        del tenant_id, connector_type
        return ConnectorExecResult(True, None, f"v-{execution_id}-{step_number}", 1, False, None)

    async def rollback(
        self, tenant_id: str, connector_type: str, original_action_id: str
    ) -> ConnectorExecResult:
        del tenant_id, connector_type
        return ConnectorExecResult(True, None, f"rb-{original_action_id}", 2, False, None)
