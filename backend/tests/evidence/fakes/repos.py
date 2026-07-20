"""In-memory fakes for evidence application tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

from evidence.application.ports.i_unit_of_work import IEventPublisher, IUnitOfWork
from evidence.domain.value_objects.identifiers import (
    AttackActionRef,
    EvidenceChainId,
    ExecutionEvidenceId,
    OperationRef,
    TenantId,
)

if TYPE_CHECKING:
    from evidence.domain.aggregates.evidence_chain import EvidenceChain
    from evidence.domain.aggregates.execution_evidence import ExecutionEvidence
    from evidence.domain.events.base import BaseDomainEvent


class InMemoryEvidenceRepository:
    def __init__(self) -> None:
        self.by_id: dict[str, ExecutionEvidence] = {}

    async def save(self, evidence: ExecutionEvidence) -> None:
        self.by_id[str(evidence.evidence_id)] = evidence

    async def find_by_id(
        self, evidence_id: ExecutionEvidenceId, tenant_id: TenantId
    ) -> ExecutionEvidence | None:
        e = self.by_id.get(str(evidence_id))
        if e is None or e.tenant_id != tenant_id:
            return None
        return e

    async def find_by_action(
        self, action_ref: AttackActionRef, tenant_id: TenantId
    ) -> list[ExecutionEvidence]:
        return [
            e
            for e in self.by_id.values()
            if e.tenant_id == tenant_id and e.action_ref == action_ref
        ]

    async def find_by_operation(
        self,
        operation_ref: OperationRef,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[ExecutionEvidence]:
        items = [
            e
            for e in self.by_id.values()
            if e.tenant_id == tenant_id and e.operation_ref == operation_ref
        ]
        return items[offset : offset + limit]


class InMemoryChainRepository:
    def __init__(self) -> None:
        self.by_id: dict[str, EvidenceChain] = {}
        self.by_operation: dict[str, EvidenceChain] = {}

    async def save(self, chain: EvidenceChain) -> None:
        self.by_id[str(chain.chain_id)] = chain
        self.by_operation[f"{chain.tenant_id}:{chain.operation_ref}"] = chain

    async def find_by_id(
        self, chain_id: EvidenceChainId, tenant_id: TenantId
    ) -> EvidenceChain | None:
        c = self.by_id.get(str(chain_id))
        if c is None or c.tenant_id != tenant_id:
            return None
        return c

    async def find_by_operation(
        self, operation_ref: OperationRef, tenant_id: TenantId
    ) -> EvidenceChain | None:
        return self.by_operation.get(f"{tenant_id}:{operation_ref}")


class FakeEvidenceUnitOfWork(IUnitOfWork):
    def __init__(
        self,
        evidence: InMemoryEvidenceRepository | None = None,
        chains: InMemoryChainRepository | None = None,
    ) -> None:
        super().__init__()
        self.evidence = evidence or InMemoryEvidenceRepository()
        self.chains = chains or InMemoryChainRepository()

    async def commit(self) -> None:
        self._committed = True

    async def rollback(self) -> None:
        self._committed = False


class FakeEventPublisher(IEventPublisher):
    def __init__(self) -> None:
        self.published: list[BaseDomainEvent] = []

    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        self.published.extend(events)
