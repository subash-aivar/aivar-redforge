
"""Repository interfaces for the evidence context."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from evidence.domain.aggregates.evidence_chain import EvidenceChain
    from evidence.domain.aggregates.execution_evidence import ExecutionEvidence
    from evidence.domain.value_objects.identifiers import (
        AttackActionRef,
        EvidenceChainId,
        ExecutionEvidenceId,
        OperationRef,
        TenantId,
    )


class IExecutionEvidenceRepository(ABC):
    @abstractmethod
    async def save(self, evidence: ExecutionEvidence) -> None: ...

    @abstractmethod
    async def find_by_id(
        self, evidence_id: ExecutionEvidenceId, tenant_id: TenantId
    ) -> ExecutionEvidence | None: ...

    @abstractmethod
    async def find_by_action(
        self, action_ref: AttackActionRef, tenant_id: TenantId
    ) -> list[ExecutionEvidence]: ...

    @abstractmethod
    async def find_by_operation(
        self,
        operation_ref: OperationRef,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[ExecutionEvidence]: ...


class IEvidenceChainRepository(ABC):
    @abstractmethod
    async def save(self, chain: EvidenceChain) -> None: ...

    @abstractmethod
    async def find_by_id(
        self, chain_id: EvidenceChainId, tenant_id: TenantId
    ) -> EvidenceChain | None: ...

    @abstractmethod
    async def find_by_operation(
        self, operation_ref: OperationRef, tenant_id: TenantId
    ) -> EvidenceChain | None: ...
