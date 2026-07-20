"""In-memory fakes for execution application tests."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from execution.application.ports.i_unit_of_work import IEventPublisher, IUnitOfWork
from execution.domain.value_objects.enums import KillSwitchScope
from execution.domain.value_objects.execution_vos import ScopeSnapshot
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

if TYPE_CHECKING:
    from execution.domain.aggregates.attack_action import AttackAction
    from execution.domain.aggregates.execution_journal import ExecutionJournal
    from execution.domain.aggregates.execution_worker import ExecutionWorker
    from execution.domain.aggregates.kill_switch_state import KillSwitchState
    from execution.domain.events.base import BaseDomainEvent


class InMemoryKillSwitchRepository:
    def __init__(self) -> None:
        self.items: dict[str, KillSwitchState] = {}

    def _key(self, tenant: TenantId, scope: KillSwitchScope, scope_ref: UUID) -> str:
        return f"{tenant}:{scope.value}:{scope_ref}"

    async def save(self, kill_switch: KillSwitchState) -> None:
        self.items[
            self._key(kill_switch.tenant_id, kill_switch.scope, kill_switch.scope_ref)
        ] = kill_switch

    async def find_by_id(
        self, kill_switch_id: KillSwitchId, tenant_id: TenantId
    ) -> KillSwitchState | None:
        for ks in self.items.values():
            if ks.kill_switch_id == kill_switch_id and ks.tenant_id == tenant_id:
                return ks
        return None

    async def find_by_scope(
        self,
        tenant_id: TenantId,
        scope: KillSwitchScope,
        scope_ref: UUID,
    ) -> KillSwitchState | None:
        return self.items.get(self._key(tenant_id, scope, scope_ref))

    async def find_platform_wide(self, tenant_id: TenantId) -> KillSwitchState | None:
        return await self.find_by_scope(
            tenant_id, KillSwitchScope.PLATFORM_WIDE, tenant_id.value
        )


class InMemoryJournalRepository:
    def __init__(self) -> None:
        self.by_id: dict[str, ExecutionJournal] = {}
        self.by_engagement: dict[str, ExecutionJournal] = {}

    async def save(self, journal: ExecutionJournal) -> None:
        self.by_id[str(journal.journal_id)] = journal
        self.by_engagement[f"{journal.tenant_id}:{journal.engagement_id}"] = journal

    async def find_by_id(
        self, journal_id: ExecutionJournalId, tenant_id: TenantId
    ) -> ExecutionJournal | None:
        j = self.by_id.get(str(journal_id))
        if j is None or j.tenant_id != tenant_id:
            return None
        return j

    async def find_by_engagement(
        self, engagement_id: EngagementId, tenant_id: TenantId
    ) -> ExecutionJournal | None:
        return self.by_engagement.get(f"{tenant_id}:{engagement_id}")


class InMemoryAttackActionRepository:
    def __init__(self) -> None:
        self.items: dict[str, AttackAction] = {}

    async def save(self, action: AttackAction) -> None:
        self.items[str(action.action_id)] = action

    async def find_by_id(
        self, action_id: AttackActionId, tenant_id: TenantId
    ) -> AttackAction | None:
        a = self.items.get(str(action_id))
        if a is None or a.tenant_id != tenant_id:
            return None
        return a

    async def find_by_operation(
        self,
        operation_id: OperationId,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AttackAction]:
        matched = [
            a
            for a in self.items.values()
            if a.operation_id == operation_id and a.tenant_id == tenant_id
        ]
        return matched[offset : offset + limit]

    async def find_non_terminal_by_step(
        self,
        step_id: ExecutionStepId,
        tenant_id: TenantId,
    ) -> AttackAction | None:
        for a in self.items.values():
            if (
                a.step_ref.step_id == step_id
                and a.tenant_id == tenant_id
                and not a.is_terminal()
            ):
                return a
        return None

    async def find_in_flight_by_engagement(
        self, engagement_id: EngagementId, tenant_id: TenantId
    ) -> list[AttackAction]:
        return [
            a
            for a in self.items.values()
            if a.engagement_id == engagement_id
            and a.tenant_id == tenant_id
            and not a.is_terminal()
        ]


class InMemoryWorkerRepository:
    def __init__(self) -> None:
        self.items: dict[str, ExecutionWorker] = {}

    async def save(self, worker: ExecutionWorker) -> None:
        self.items[str(worker.worker_id)] = worker

    async def find_by_id(
        self, worker_id: ExecutionWorkerId, tenant_id: TenantId
    ) -> ExecutionWorker | None:
        w = self.items.get(str(worker_id))
        if w is None or w.tenant_id != tenant_id:
            return None
        return w

    async def find_available_by_capability(
        self,
        tenant_id: TenantId,
        technique_id: str,
        network_zone: str | None = None,
    ) -> list[ExecutionWorker]:
        result = []
        for w in self.items.values():
            if w.tenant_id != tenant_id or not w.is_available():
                continue
            if technique_id not in w.capabilities:
                continue
            if network_zone is not None and w.network_zone != network_zone:
                continue
            result.append(w)
        return result

    async def list_available(
        self,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[ExecutionWorker]:
        matched = [w for w in self.items.values() if w.tenant_id == tenant_id and w.is_available()]
        return matched[offset : offset + limit]


class FakeUnitOfWork(IUnitOfWork):
    def __init__(
        self,
        kill_switches: InMemoryKillSwitchRepository | None = None,
        journals: InMemoryJournalRepository | None = None,
        attack_actions: InMemoryAttackActionRepository | None = None,
        workers: InMemoryWorkerRepository | None = None,
    ) -> None:
        super().__init__()
        self.kill_switches = kill_switches or InMemoryKillSwitchRepository()
        self.journals = journals or InMemoryJournalRepository()
        self.attack_actions = attack_actions or InMemoryAttackActionRepository()
        self.workers = workers or InMemoryWorkerRepository()

    async def commit(self) -> None:
        self._committed = True

    async def rollback(self) -> None:
        pass


class FakeEventPublisher(IEventPublisher):
    def __init__(self) -> None:
        self.events: list[BaseDomainEvent] = []

    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        self.events.extend(events)


class ConfigurableEngagementScope:
    def __init__(self, snapshot: ScopeSnapshot) -> None:
        self.snapshot = snapshot

    async def get_scope_snapshot(
        self,
        engagement_id: EngagementId,
        tenant_id: TenantId,
    ) -> ScopeSnapshot:
        _ = (engagement_id, tenant_id)
        return self.snapshot
