"""Recovery orchestration helpers."""

from __future__ import annotations

from incident.domain.aggregates.recovery_milestone import RecoveryMilestone
from incident.domain.value_objects.enums import RecoveryMilestoneStatus


class RecoveryService:
    def all_completed(self, milestones: list[RecoveryMilestone]) -> bool:
        if not milestones:
            return False
        return all(m.status == RecoveryMilestoneStatus.COMPLETED for m in milestones)
