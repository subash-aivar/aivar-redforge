from __future__ import annotations

from automated_action.domain.aggregates.automation_execution import AutomationExecution


class ExecutionReplayService:
    def can_replay(self, execution: AutomationExecution) -> bool:
        return execution.status.value in {"FAILED", "COMPLETED"}
