"""AutomationPolicy aggregate — per-tenant kill switch and budgets."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from playbook.domain.events.playbook_events import (
    AutomationKillSwitchActivated,
    AutomationKillSwitchReset,
)
from playbook.domain.exceptions.domain_exceptions import DomainInvariantViolation, KillSwitchActive
from playbook.domain.value_objects.enums import ConnectorType, KillSwitchState
from playbook.domain.value_objects.identifiers import TenantId


class AutomationPolicy:
    __slots__ = (
        "_pending_events",
        "allowed_connector_types",
        "kill_switch_state",
        "kill_switch_triggered_at",
        "kill_switch_triggered_by",
        "max_actions_per_hour",
        "max_concurrent_executions",
        "tenant_id",
        "updated_at",
    )

    def __init__(
        self,
        tenant_id: TenantId,
        kill_switch_state: KillSwitchState = KillSwitchState.ARMED,
        *,
        kill_switch_triggered_at: datetime | None = None,
        kill_switch_triggered_by: str | None = None,
        max_concurrent_executions: int = 5,
        max_actions_per_hour: int = 100,
        allowed_connector_types: list[ConnectorType] | None = None,
        updated_at: datetime | None = None,
    ) -> None:
        self.tenant_id = tenant_id
        self.kill_switch_state = kill_switch_state
        self.kill_switch_triggered_at = kill_switch_triggered_at
        self.kill_switch_triggered_by = kill_switch_triggered_by
        self.max_concurrent_executions = max_concurrent_executions
        self.max_actions_per_hour = max_actions_per_hour
        self.allowed_connector_types = allowed_connector_types
        self.updated_at = updated_at or datetime.now(UTC)
        self._pending_events: list[Any] = []

    def pop_events(self) -> list[Any]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    @classmethod
    def default(cls, tenant_id: TenantId) -> AutomationPolicy:
        return cls(tenant_id)

    def assert_armed(self) -> None:
        if self.kill_switch_state == KillSwitchState.TRIGGERED:
            raise KillSwitchActive("automation kill switch is TRIGGERED")

    def activate_kill_switch(self, activated_by: str, reason: str) -> None:
        if self.kill_switch_state == KillSwitchState.TRIGGERED:
            raise DomainInvariantViolation("kill switch already TRIGGERED")
        now = datetime.now(UTC)
        self.kill_switch_state = KillSwitchState.TRIGGERED
        self.kill_switch_triggered_at = now
        self.kill_switch_triggered_by = activated_by
        self.updated_at = now
        self._pending_events.append(
            AutomationKillSwitchActivated(
                tenant_id=str(self.tenant_id),
                aggregate_id=str(self.tenant_id),
                activated_by=activated_by,
                activated_at=now.isoformat(),
                reason=reason,
            )
        )

    def reset_kill_switch(self, reset_by: str) -> None:
        if self.kill_switch_state != KillSwitchState.TRIGGERED:
            raise DomainInvariantViolation("kill switch is not TRIGGERED")
        now = datetime.now(UTC)
        self.kill_switch_state = KillSwitchState.ARMED
        self.kill_switch_triggered_at = None
        self.kill_switch_triggered_by = None
        self.updated_at = now
        self._pending_events.append(
            AutomationKillSwitchReset(
                tenant_id=str(self.tenant_id),
                aggregate_id=str(self.tenant_id),
                reset_by=reset_by,
                reset_at=now.isoformat(),
            )
        )

    def update_budgets(
        self,
        *,
        max_concurrent_executions: int | None = None,
        max_actions_per_hour: int | None = None,
        allowed_connector_types: list[ConnectorType] | None = None,
    ) -> None:
        if max_concurrent_executions is not None:
            if not 1 <= max_concurrent_executions <= 50:
                raise DomainInvariantViolation("max_concurrent_executions must be 1..50")
            self.max_concurrent_executions = max_concurrent_executions
        if max_actions_per_hour is not None:
            if not 1 <= max_actions_per_hour <= 1000:
                raise DomainInvariantViolation("max_actions_per_hour must be 1..1000")
            self.max_actions_per_hour = max_actions_per_hour
        if allowed_connector_types is not None:
            self.allowed_connector_types = list(allowed_connector_types)
        self.updated_at = datetime.now(UTC)
