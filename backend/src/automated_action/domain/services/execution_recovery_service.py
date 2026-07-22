from __future__ import annotations

from datetime import UTC, datetime, timedelta

from automated_action.domain.aggregates.automated_action_record import AutomatedActionRecord
from automated_action.domain.value_objects.enums import ActionRecordStatus


class ExecutionRecoveryService:
    def is_stale(self, record: AutomatedActionRecord, *, minutes: int = 5) -> bool:
        if record.status != ActionRecordStatus.PENDING:
            return False
        return datetime.now(UTC) - record.attempted_at > timedelta(minutes=minutes)
