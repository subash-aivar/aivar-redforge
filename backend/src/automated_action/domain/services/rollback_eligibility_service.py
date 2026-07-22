from __future__ import annotations

from datetime import UTC, datetime, timedelta

from automated_action.domain.aggregates.automated_action_record import AutomatedActionRecord


class RollbackEligibilityService:
    def is_eligible(self, record: AutomatedActionRecord, *, max_window_hours: int = 24) -> bool:
        if not record.rollback_available:
            return False
        if record.completed_at is None:
            return False
        return datetime.now(UTC) - record.completed_at <= timedelta(hours=max_window_hours)
