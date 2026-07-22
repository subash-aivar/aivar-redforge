from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime

from automated_action.domain.aggregates.automated_action_record import AutomatedActionRecord
from automated_action.domain.aggregates.automation_execution import AutomationExecution
from automated_action.domain.aggregates.rollback_record import RollbackRecord
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


class IAutomationExecutionRepository(ABC):
    @abstractmethod
    async def save(self, execution: AutomationExecution, tenant_id: TenantId) -> None: ...

    @abstractmethod
    async def get(
        self, execution_id: AutomationExecutionId, tenant_id: TenantId
    ) -> AutomationExecution | None: ...

    @abstractmethod
    async def find_by_status(
        self, tenant_id: TenantId, status: ExecutionStatus, limit: int
    ) -> list[AutomationExecution]: ...

    @abstractmethod
    async def find_pending_recovery(self, older_than_minutes: int) -> list[AutomationExecution]: ...

    @abstractmethod
    async def list(
        self,
        tenant_id: TenantId,
        *,
        status_filter: str | None,
        playbook_id_filter: str | None,
        page: int,
        page_size: int,
    ) -> list[AutomationExecution]: ...


class IAutomatedActionRecordRepository(ABC):
    @abstractmethod
    async def append(self, record: AutomatedActionRecord, tenant_id: TenantId) -> None: ...

    @abstractmethod
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
    ) -> None: ...

    @abstractmethod
    async def find_by_execution(
        self, execution_id: AutomationExecutionId, tenant_id: TenantId
    ) -> list[AutomatedActionRecord]: ...

    @abstractmethod
    async def find_pending_recovery(
        self, older_than_minutes: int
    ) -> list[AutomatedActionRecord]: ...


class IRollbackRecordRepository(ABC):
    @abstractmethod
    async def append(self, record: RollbackRecord, tenant_id: TenantId) -> None: ...

    @abstractmethod
    async def update_status(
        self,
        rollback_id: RollbackRecordId,
        tenant_id: TenantId,
        status: RollbackStatus,
        completed_at: datetime | None,
        failure_reason: str | None,
    ) -> None: ...

    @abstractmethod
    async def find_by_execution(
        self, execution_id: AutomationExecutionId, tenant_id: TenantId
    ) -> list[RollbackRecord]: ...
