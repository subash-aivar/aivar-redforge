from __future__ import annotations

from dataclasses import dataclass

from automated_action.domain.exceptions.domain_exceptions import KillSwitchActive, PolicyDenied


@dataclass(frozen=True, slots=True)
class PolicySnapshot:
    kill_switch_triggered: bool
    max_concurrent_executions: int
    max_actions_per_hour: int
    change_freeze: bool = False
    maintenance_window: bool = False
    business_hours_only: bool = False
    in_business_hours: bool = True


class ExecutionPolicyService:
    def evaluate(
        self,
        policy: PolicySnapshot,
        *,
        running_count: int,
        actions_last_hour: int,
    ) -> None:
        if policy.kill_switch_triggered:
            raise KillSwitchActive("kill switch TRIGGERED")
        if policy.change_freeze:
            raise PolicyDenied("change freeze active")
        if policy.maintenance_window:
            raise PolicyDenied("maintenance window")
        if policy.business_hours_only and not policy.in_business_hours:
            raise PolicyDenied("outside business hours")
        if running_count >= policy.max_concurrent_executions:
            raise PolicyDenied("max concurrent executions")
        if actions_last_hour >= policy.max_actions_per_hour:
            raise PolicyDenied("max actions per hour")
