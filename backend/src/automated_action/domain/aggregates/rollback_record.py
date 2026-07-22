from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from automated_action.domain.value_objects.enums import RollbackStatus
from automated_action.domain.value_objects.identifiers import (
    AutomatedActionRecordId,
    AutomationExecutionId,
    RollbackRecordId,
    TenantId,
)


@dataclass
class RollbackRecord:
    rollback_id: RollbackRecordId
    tenant_id: TenantId
    original_record_id: AutomatedActionRecordId
    execution_id: AutomationExecutionId
    rollback_status: RollbackStatus
    initiated_by: str
    initiated_at: datetime
    completed_at: datetime | None
    failure_reason: str | None

    @classmethod
    def create(
        cls,
        tenant_id: TenantId,
        original_record_id: AutomatedActionRecordId,
        execution_id: AutomationExecutionId,
        initiated_by: str,
    ) -> RollbackRecord:
        return cls(
            RollbackRecordId.generate(),
            tenant_id,
            original_record_id,
            execution_id,
            RollbackStatus.PENDING,
            initiated_by,
            datetime.now(UTC),
            None,
            None,
        )

    def mark_completed(self) -> None:
        self.rollback_status = RollbackStatus.COMPLETED
        self.completed_at = datetime.now(UTC)

    def mark_failed(self, reason: str) -> None:
        self.rollback_status = RollbackStatus.FAILED
        self.failure_reason = reason
        self.completed_at = datetime.now(UTC)
