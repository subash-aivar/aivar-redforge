from __future__ import annotations


class ExecutionBudgetService:
    def allows(
        self,
        *,
        running_count: int,
        max_concurrent: int,
        actions_last_hour: int,
        max_actions_per_hour: int,
    ) -> tuple[bool, str]:
        if running_count >= max_concurrent:
            return False, "max_concurrent_executions"
        if actions_last_hour >= max_actions_per_hour:
            return False, "max_actions_per_hour"
        return True, "ok"
