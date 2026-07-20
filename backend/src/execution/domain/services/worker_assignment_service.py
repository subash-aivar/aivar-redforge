"""WorkerAssignmentService — route steps to capable, healthy workers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from execution.domain.exceptions.domain_exceptions import WorkerCapabilityInsufficient
from execution.domain.services.worker_capability_verification_service import (
    WorkerCapabilityVerificationService,
)

if TYPE_CHECKING:
    from execution.domain.aggregates.execution_worker import ExecutionWorker
    from execution.domain.repositories.i_repositories import IExecutionWorkerRepository
    from execution.domain.value_objects.execution_vos import TechniqueRef
    from execution.domain.value_objects.identifiers import TenantId


class WorkerAssignmentService:
    def __init__(
        self,
        workers: IExecutionWorkerRepository,
        capability_service: WorkerCapabilityVerificationService | None = None,
    ) -> None:
        self._workers = workers
        self._capability = capability_service or WorkerCapabilityVerificationService()

    async def select_worker(
        self,
        tenant_id: TenantId,
        technique: TechniqueRef,
        network_zone: str | None = None,
        preferred: ExecutionWorker | None = None,
    ) -> ExecutionWorker:
        if preferred is not None:
            if not self._capability.verify(preferred, technique):
                raise WorkerCapabilityInsufficient(
                    str(preferred.worker_id), technique.technique_id
                )
            if not preferred.is_available():
                raise WorkerCapabilityInsufficient(
                    str(preferred.worker_id), technique.technique_id
                )
            return preferred

        candidates = await self._workers.find_available_by_capability(
            tenant_id, technique.technique_id, network_zone
        )
        for worker in candidates:
            if self._capability.verify(worker, technique) and worker.is_available():
                return worker
        raise WorkerCapabilityInsufficient("none", technique.technique_id)
