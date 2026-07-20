"""Execution worker API routes."""

from __future__ import annotations

from dataclasses import asdict
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from execution.api.dependencies import (
    ExecutionServiceDep,
    PrincipalIdDep,
    TenantIdDep,
)
from execution.api.schemas.execution_schemas import (
    ExecutionWorkerResponse,
    HeartbeatRequest,
    RegisterWorkerRequest,
)
from execution.application.commands.execution_commands import (
    DecommissionExecutionWorker,
    RecordWorkerHeartbeat,
    RegisterExecutionWorker,
)
from execution.application.queries.execution_queries import (
    GetExecutionWorker,
    ListAvailableWorkers,
)
from redforge.api.security import TenantContext, require_permission
from redforge.domain.identity.value_objects import Permission

workers_router = APIRouter()


@workers_router.post("", response_model=ExecutionWorkerResponse, status_code=201)
async def register_worker(
    body: RegisterWorkerRequest,
    service: ExecutionServiceDep,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ADMIN)),
) -> ExecutionWorkerResponse:
    dto = await service.register_execution_worker(
        RegisterExecutionWorker(
            tenant_id=tenant_id,
            worker_type=body.worker_type,
            network_zone=body.network_zone,
            techniques=tuple(body.techniques),
            trust_level=body.trust_level,
            signer_operator_id=principal_id,
            signature=body.signature,
        )
    )
    return ExecutionWorkerResponse.model_validate(asdict(dto))


@workers_router.post("/{worker_id}/decommission", response_model=ExecutionWorkerResponse)
async def decommission_worker(
    worker_id: UUID,
    service: ExecutionServiceDep,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ADMIN)),
) -> ExecutionWorkerResponse:
    dto = await service.decommission_execution_worker(
        DecommissionExecutionWorker(
            tenant_id=tenant_id,
            worker_id=worker_id,
            authority_operator_id=principal_id,
        )
    )
    return ExecutionWorkerResponse.model_validate(asdict(dto))


@workers_router.post("/{worker_id}/heartbeat", response_model=ExecutionWorkerResponse)
async def worker_heartbeat(
    worker_id: UUID,
    body: HeartbeatRequest,
    service: ExecutionServiceDep,
    tenant_id: TenantIdDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_OPERATOR)),
) -> ExecutionWorkerResponse:
    dto = await service.record_worker_heartbeat(
        RecordWorkerHeartbeat(
            tenant_id=tenant_id,
            worker_id=worker_id,
            health_status=body.health_status,
        )
    )
    return ExecutionWorkerResponse.model_validate(asdict(dto))


@workers_router.get("/{worker_id}", response_model=ExecutionWorkerResponse)
async def get_worker(
    worker_id: UUID,
    service: ExecutionServiceDep,
    tenant_id: TenantIdDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_READER)),
) -> ExecutionWorkerResponse:
    dto = await service.get_execution_worker(
        GetExecutionWorker(tenant_id=tenant_id, worker_id=worker_id)
    )
    return ExecutionWorkerResponse.model_validate(asdict(dto))


@workers_router.get("", response_model=list[ExecutionWorkerResponse])
async def list_available(
    service: ExecutionServiceDep,
    tenant_id: TenantIdDep,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_READER)),
) -> list[ExecutionWorkerResponse]:
    dtos = await service.list_available_workers(
        ListAvailableWorkers(tenant_id=tenant_id, limit=limit, offset=offset)
    )
    return [ExecutionWorkerResponse.model_validate(asdict(d)) for d in dtos]
