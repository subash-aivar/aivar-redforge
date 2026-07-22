"""Match external trigger events to playbook trigger configs."""

from __future__ import annotations

from playbook.domain.value_objects.definitions import TriggerCondition
from playbook.domain.value_objects.enums import TriggerSourceContext


class TriggerMatchingService:
    def matches(
        self,
        condition: TriggerCondition,
        *,
        source_context: TriggerSourceContext,
        trigger_type: str,
        severity: str | None,
        asset_tags: list[str] | None,
    ) -> bool:
        if condition.source_context != source_context:
            return False
        if condition.trigger_type != trigger_type and condition.trigger_type != "*":
            return False
        if condition.severity_threshold and severity:
            order = [
                "LOW",
                "MEDIUM",
                "HIGH",
                "CRITICAL",
                "P4_LOW",
                "P3_MEDIUM",
                "P2_HIGH",
                "P1_CRITICAL",
            ]
            try:
                if order.index(severity) < order.index(condition.severity_threshold):
                    return False
            except ValueError:
                if severity != condition.severity_threshold:
                    return False
        if condition.asset_tag_filter:
            tags = set(asset_tags or [])
            if not tags.intersection(condition.asset_tag_filter):
                return False
        return True
