"""Playbook lifecycle helpers."""

from __future__ import annotations

from playbook.domain.value_objects.definitions import ActionStepDefinition
from playbook.domain.value_objects.enums import ActionImpactLevel


class PlaybookLifecycleService:
    def max_impact(self, steps: list[ActionStepDefinition]) -> ActionImpactLevel:
        order = [
            ActionImpactLevel.LOW,
            ActionImpactLevel.MEDIUM,
            ActionImpactLevel.HIGH,
            ActionImpactLevel.CRITICAL,
        ]
        if not steps:
            return ActionImpactLevel.LOW
        return max(steps, key=lambda s: order.index(s.impact_level)).impact_level
