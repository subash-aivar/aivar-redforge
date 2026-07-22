from __future__ import annotations

from datetime import UTC, datetime, timedelta

from automated_action.domain.aggregates.automated_action_record import AutomatedActionRecord
from automated_action.domain.aggregates.automation_execution import AutomationExecution
from automated_action.domain.aggregates.rollback_record import RollbackRecord
from automated_action.domain.repositories.i_automation_repositories import (
    IAutomatedActionRecordRepository,
    IAutomationExecutionRepository,
    IRollbackRecordRepository,
)
from automated_action.domain.value_objects.enums import (
    ActionOutcome,
    ActionRecordStatus,
    ConnectorFailureMode,
    ExecutionStatus,
    RollbackStatus,
)
from automated_action.domain.value_objects.identifiers import (
    AutomatedActionRecordId,
    AutomationExecutionId,
    RollbackRecordId,
    TenantId,
)


class InMemoryAutomationExecutionRepository(IAutomationExecutionRepository):
    def __init__(self) -> None:
        self._items: dict[str, dict[str, AutomationExecution]] = {}

    async def save(self, execution: AutomationExecution, tenant_id: TenantId) -> None:
        self._items.setdefault(str(tenant_id), {})[str(execution.execution_id)] = execution

    async def get(
        self, execution_id: AutomationExecutionId, tenant_id: TenantId
    ) -> AutomationExecution | None:
        return self._items.get(str(tenant_id), {}).get(str(execution_id))

    async def find_by_status(
        self, tenant_id: TenantId, status: ExecutionStatus, limit: int
    ) -> list[AutomationExecution]:
        rows = [e for e in self._items.get(str(tenant_id), {}).values() if e.status == status]
        return rows[:limit]

    async def find_pending_recovery(self, older_than_minutes: int) -> list[AutomationExecution]:
        cutoff = datetime.now(UTC) - timedelta(minutes=older_than_minutes)
        out: list[AutomationExecution] = []
        for tenant_rows in self._items.values():
            for e in tenant_rows.values():
                if e.status == ExecutionStatus.PENDING and e.started_at < cutoff:
                    out.append(e)
        return out

    async def list(
        self,
        tenant_id: TenantId,
        *,
        status_filter: str | None,
        playbook_id_filter: str | None,
        page: int,
        page_size: int,
    ) -> list[AutomationExecution]:
        rows = list(self._items.get(str(tenant_id), {}).values())
        if status_filter:
            rows = [r for r in rows if r.status.value == status_filter]
        if playbook_id_filter:
            rows = [r for r in rows if r.playbook_ref.playbook_id == playbook_id_filter]
        start = (page - 1) * page_size
        return rows[start : start + page_size]


class InMemoryAutomatedActionRecordRepository(IAutomatedActionRecordRepository):
    def __init__(self) -> None:
        self._items: dict[str, dict[str, AutomatedActionRecord]] = {}

    async def append(self, record: AutomatedActionRecord, tenant_id: TenantId) -> None:
        self._items.setdefault(str(tenant_id), {})[str(record.record_id)] = record

    async def update_status(
        self,
        record_id: AutomatedActionRecordId,
        tenant_id: TenantId,
        status: ActionRecordStatus,
        outcome: ActionOutcome | None,
        external_reference: str | None,
        failure_mode: ConnectorFailureMode | None,
        completed_at: datetime,
        duration_ms: int,
    ) -> None:
        rec = self._items.get(str(tenant_id), {}).get(str(record_id))
        if rec is None:
            return
        rec.status = status
        rec.outcome = outcome
        rec.external_reference = external_reference
        rec.failure_mode = failure_mode
        rec.completed_at = completed_at
        rec.duration_ms = duration_ms

    async def find_by_execution(
        self, execution_id: AutomationExecutionId, tenant_id: TenantId
    ) -> list[AutomatedActionRecord]:
        return [
            r
            for r in self._items.get(str(tenant_id), {}).values()
            if r.execution_id.value == execution_id.value
        ]

    async def find_pending_recovery(self, older_than_minutes: int) -> list[AutomatedActionRecord]:
        cutoff = datetime.now(UTC) - timedelta(minutes=older_than_minutes)
        out: list[AutomatedActionRecord] = []
        for rows in self._items.values():
            for r in rows.values():
                if r.status == ActionRecordStatus.PENDING and r.attempted_at < cutoff:
                    out.append(r)
        return out


class InMemoryRollbackRecordRepository(IRollbackRecordRepository):
    def __init__(self) -> None:
        self._items: dict[str, dict[str, RollbackRecord]] = {}

    async def append(self, record: RollbackRecord, tenant_id: TenantId) -> None:
        self._items.setdefault(str(tenant_id), {})[str(record.rollback_id)] = record

    async def update_status(
        self,
        rollback_id: RollbackRecordId,
        tenant_id: TenantId,
        status: RollbackStatus,
        completed_at: datetime | None,
        failure_reason: str | None,
    ) -> None:
        rec = self._items.get(str(tenant_id), {}).get(str(rollback_id))
        if rec is None:
            return
        rec.rollback_status = status
        rec.completed_at = completed_at
        rec.failure_reason = failure_reason

    async def find_by_execution(
        self, execution_id: AutomationExecutionId, tenant_id: TenantId
    ) -> list[RollbackRecord]:
        return [
            r
            for r in self._items.get(str(tenant_id), {}).values()
            if r.execution_id.value == execution_id.value
        ]
