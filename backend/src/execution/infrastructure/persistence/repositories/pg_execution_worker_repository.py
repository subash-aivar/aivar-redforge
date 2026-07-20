"""PgExecutionWorkerRepository."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import select, update

from execution.domain.aggregates.execution_worker import ExecutionWorker
from execution.domain.exceptions.domain_exceptions import OptimisticLockConflict
from execution.domain.repositories.i_repositories import IExecutionWorkerRepository
from execution.domain.value_objects.enums import (
    WorkerHealthStatus,
    WorkerTrustLevel,
    WorkerType,
)
from execution.domain.value_objects.identifiers import (
    ExecutionWorkerId,
    OperatorId,
    TenantId,
)
from execution.infrastructure.persistence.models.execution_models import ExecutionWorkerModel

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

_AVAILABLE = (
    WorkerHealthStatus.HEALTHY.value,
    WorkerHealthStatus.DEGRADED.value,
)


class PgExecutionWorkerRepository(IExecutionWorkerRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, worker: ExecutionWorker) -> None:
        existing = await self._session.get(ExecutionWorkerModel, worker.worker_id.value)
        if existing is None:
            model = self._to_model(worker)
            model.row_version = 1
            self._session.add(model)
            worker._version = 1
            return
        if existing.tenant_id != worker.tenant_id.value:
            raise OptimisticLockConflict(str(worker.worker_id), worker.version, -1)
        expected = worker.version
        stmt = (
            update(ExecutionWorkerModel)
            .where(
                ExecutionWorkerModel.id == worker.worker_id.value,
                ExecutionWorkerModel.row_version == expected,
            )
            .values(
                health_status=worker.health_status.value,
                last_heartbeat_at=worker.last_heartbeat_at,
                decommissioned_at=worker.decommissioned_at,
                updated_at=worker.updated_at,
                row_version=expected + 1,
            )
        )
        result = await self._session.execute(stmt)
        if result.rowcount == 0:  # type: ignore[attr-defined]
            raise OptimisticLockConflict(
                str(worker.worker_id), expected, existing.row_version
            )
        worker._version = expected + 1

    async def find_by_id(
        self, worker_id: ExecutionWorkerId, tenant_id: TenantId
    ) -> ExecutionWorker | None:
        model = await self._session.get(ExecutionWorkerModel, worker_id.value)
        if model is None or model.tenant_id != tenant_id.value:
            return None
        return self._to_domain(model)

    async def find_available_by_capability(
        self,
        tenant_id: TenantId,
        technique_id: str,
        network_zone: str | None = None,
    ) -> list[ExecutionWorker]:
        stmt = select(ExecutionWorkerModel).where(
            ExecutionWorkerModel.tenant_id == tenant_id.value,
            ExecutionWorkerModel.health_status.in_(_AVAILABLE),
        )
        if network_zone is not None:
            stmt = stmt.where(ExecutionWorkerModel.network_zone == network_zone)
        result = await self._session.execute(stmt)
        workers = [self._to_domain(m) for m in result.scalars().all()]
        return [w for w in workers if technique_id in w.capabilities]

    async def list_available(
        self,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[ExecutionWorker]:
        stmt = (
            select(ExecutionWorkerModel)
            .where(
                ExecutionWorkerModel.tenant_id == tenant_id.value,
                ExecutionWorkerModel.health_status.in_(_AVAILABLE),
            )
            .limit(limit)
            .offset(offset)
        )
        result = await self._session.execute(stmt)
        return [self._to_domain(m) for m in result.scalars().all()]

    def _to_model(self, worker: ExecutionWorker) -> ExecutionWorkerModel:
        return ExecutionWorkerModel(
            id=worker.worker_id.value,
            tenant_id=worker.tenant_id.value,
            worker_type=worker.worker_type.value,
            trust_level=worker.trust_level.value,
            health_status=worker.health_status.value,
            network_zone=worker.network_zone,
            capabilities_json=sorted(worker.capabilities),
            manifest_hash=worker.manifest_hash,
            signer_operator_id=worker.signer_operator_id.value,
            registered_at=worker.registered_at,
            last_heartbeat_at=worker.last_heartbeat_at,
            decommissioned_at=worker.decommissioned_at,
            created_at=worker.created_at,
            updated_at=worker.updated_at,
            row_version=worker.version,
        )

    def _to_domain(self, model: ExecutionWorkerModel) -> ExecutionWorker:
        return ExecutionWorker(
            worker_id=ExecutionWorkerId(model.id),
            tenant_id=TenantId(model.tenant_id),
            worker_type=WorkerType(model.worker_type),
            capabilities=frozenset(str(c) for c in model.capabilities_json),
            trust_level=WorkerTrustLevel(model.trust_level),
            health_status=WorkerHealthStatus(model.health_status),
            network_zone=model.network_zone,
            manifest_hash=model.manifest_hash,
            signer_operator_id=OperatorId(model.signer_operator_id),
            registered_at=model.registered_at,
            created_at=model.created_at,
            updated_at=model.updated_at,
            version=model.row_version,
            last_heartbeat_at=model.last_heartbeat_at,
            decommissioned_at=model.decommissioned_at,
        )
