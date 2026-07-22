from __future__ import annotations

from automated_action.domain.value_objects.enums import ActionImpactLevel


class AutomationExecutionService:
    def needs_runtime_auth(self, level: ActionImpactLevel) -> bool:
        return level in {ActionImpactLevel.HIGH, ActionImpactLevel.CRITICAL}
