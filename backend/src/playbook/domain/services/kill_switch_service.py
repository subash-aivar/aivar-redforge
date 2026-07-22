"""Kill switch domain operations — ADR-M35-004."""

from __future__ import annotations

from playbook.domain.aggregates.automation_policy import AutomationPolicy


class KillSwitchService:
    def activate(self, policy: AutomationPolicy, activated_by: str, reason: str) -> None:
        policy.activate_kill_switch(activated_by, reason)

    def reset(self, policy: AutomationPolicy, reset_by: str) -> None:
        policy.reset_kill_switch(reset_by)

    def is_triggered(self, policy: AutomationPolicy) -> bool:
        return policy.kill_switch_state.value == "TRIGGERED"
