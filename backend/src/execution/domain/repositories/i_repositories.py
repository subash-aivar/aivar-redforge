"""Repository interfaces for the execution context."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID

    from execution.domain.aggregates.attack_action import AttackAction
    from execution.domain.aggregates.execution_journal import ExecutionJournal
    from execution.domain.aggregates.execution_worker import ExecutionWorker
    from execution.domain.aggregates.kill_switch_state import KillSwitchState
    from execution.domain.value_objects.enums import KillSwitchScope
    from execution.domain.value_objects.identifiers import (
        AttackActionId,
        EngagementId,
        ExecutionJournalId,
        ExecutionStepId,
        ExecutionWorkerId,
        KillSwitchId,
        OperationId,
        TenantId,
    )


class IKillSwitchRepository(ABC):
    @abstractmethod
    async def save(self, kill_switch: KillSwitchState) -> None: ...

    @abstractmethod
    async def find_by_id(
        self, kill_switch_id: KillSwitchId, tenant_id: TenantId
    ) -> KillSwitchState | None: ...

    @abstractmethod
    async def find_by_scope(
        self,
        tenant_id: TenantId,
        scope: KillSwitchScope,
        scope_ref: UUID,
    ) -> KillSwitchState | None: ...

    @abstractmethod
    async def find_platform_wide(self, tenant_id: TenantId) -> KillSwitchState | None: ...


class IExecutionJournalRepository(ABC):
    @abstractmethod
    async def save(self, journal: ExecutionJournal) -> None: ...

    @abstractmethod
    async def find_by_id(
        self, journal_id: ExecutionJournalId, tenant_id: TenantId
    ) -> ExecutionJournal | None: ...

    @abstractmethod
    async def find_by_engagement(
        self, engagement_id: EngagementId, tenant_id: TenantId
    ) -> ExecutionJournal | None: ...


class IAttackActionRepository(ABC):
    @abstractmethod
    async def save(self, action: AttackAction) -> None: ...

    @abstractmethod
    async def find_by_id(
        self, action_id: AttackActionId, tenant_id: TenantId
    ) -> AttackAction | None: ...

    @abstractmethod
    async def find_by_operation(
        self,
        operation_id: OperationId,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AttackAction]: ...

    @abstractmethod
    async def find_non_terminal_by_step(
        self,
        step_id: ExecutionStepId,
        tenant_id: TenantId,
    ) -> AttackAction | None: ...

    @abstractmethod
    async def find_in_flight_by_engagement(
        self, engagement_id: EngagementId, tenant_id: TenantId
    ) -> list[AttackAction]: ...


class IExecutionWorkerRepository(ABC):
    @abstractmethod
    async def save(self, worker: ExecutionWorker) -> None: ...

    @abstractmethod
    async def find_by_id(
        self, worker_id: ExecutionWorkerId, tenant_id: TenantId
    ) -> ExecutionWorker | None: ...

    @abstractmethod
    async def find_available_by_capability(
        self,
        tenant_id: TenantId,
        technique_id: str,
        network_zone: str | None = None,
    ) -> list[ExecutionWorker]: ...

    @abstractmethod
    async def list_available(
        self,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[ExecutionWorker]: ...
