"""REST API for analytics Phase 1 + Phase 2."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from analytics.api.dependencies import get_actor_roles, get_container, get_tenant_id
from analytics.api.schemas.analytics_schemas import (
    CreateBaselineRequest,
    CreateQueryRequest,
    DefineKPIRequest,
    EvaluateAnomalyRequest,
    ExecuteQueryRequest,
    IngestEventRequest,
    RebuildRequest,
    RegisterDataSetRequest,
    TriggerKPIRequest,
)
from analytics.application.commands.analytics_commands import (
    CreateAnalyticsQueryCommand,
    CreateAnomalyBaselineCommand,
    DefineSecurityKPICommand,
    ExecuteAnalyticsQueryCommand,
    RegisterAnalyticsDataSetCommand,
    TriggerKPIComputationCommand,
    TriggerProjectionRebuildCommand,
)
from analytics.application.exceptions import (
    ApplicationForbiddenError,
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from analytics.domain.exceptions.domain_exceptions import AnalyticsDomainError
from analytics.domain.value_objects.identifiers import TenantId
from analytics.infrastructure.container import AnalyticsContainer

router = APIRouter(prefix="/analytics", tags=["analytics"])


def _map(exc: Exception) -> HTTPException:
    if isinstance(exc, ApplicationForbiddenError):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, ApplicationNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, (ApplicationValidationError, AnalyticsDomainError)):
        return HTTPException(status_code=400, detail=str(exc))
    return HTTPException(status_code=500, detail="Internal error")


@router.post("/datasets")
async def register_dataset(
    body: RegisterDataSetRequest,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AnalyticsContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.register_dataset(
            RegisterAnalyticsDataSetCommand(tenant_id, body.domain, body.schema_version, roles)
        )
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/datasets/{dataset_id}")
async def get_dataset(
    dataset_id: UUID,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AnalyticsContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.get_dataset_status(tenant_id, dataset_id, roles)
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/kpis")
async def define_kpi(
    body: DefineKPIRequest,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AnalyticsContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.define_kpi(
            DefineSecurityKPICommand(tenant_id, body.kpi_type, body.computation_schedule, roles)
        )
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/kpis/{kpi_type}")
async def get_kpi(
    kpi_type: str,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AnalyticsContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.get_kpi(tenant_id, kpi_type, roles)
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/kpis/{kpi_type}/history")
async def kpi_history(
    kpi_type: str,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AnalyticsContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    try:
        return await container.app.get_kpi_history(tenant_id, kpi_type, roles)
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/admin/kpis/compute")
async def compute_kpi(
    body: TriggerKPIRequest,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AnalyticsContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.trigger_kpi(
            TriggerKPIComputationCommand(tenant_id, body.kpi_type, roles)
        )
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/baselines")
async def create_baseline(
    body: CreateBaselineRequest,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AnalyticsContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.create_baseline(
            CreateAnomalyBaselineCommand(
                tenant_id, body.signal_type, body.method, body.window_days, roles
            )
        )
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/anomalies/evaluate")
async def evaluate_anomaly(
    body: EvaluateAnomalyRequest,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AnalyticsContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.evaluate_anomaly(
            tenant_id, body.signal_type, body.observed, roles
        )
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/anomalies")
async def list_anomalies(
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AnalyticsContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    try:
        return await container.app.list_anomalies(tenant_id, roles)
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/summary")
async def summary(
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AnalyticsContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.get_summary(tenant_id, roles)
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/internal/events")
async def ingest_event(
    body: IngestEventRequest,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AnalyticsContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.projection_worker.handle(
            tenant_id=tenant_id,
            domain=body.domain,
            event_id=body.event_id,
            event_type=body.event_type,
            event_ts=body.event_ts,
            payload=body.payload,
        )
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/admin/projections/rebuild")
async def rebuild(
    body: RebuildRequest,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AnalyticsContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.trigger_rebuild(
            TriggerProjectionRebuildCommand(tenant_id, body.domain, roles)
        )
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/admin/scheduler/tick")
async def scheduler_tick(
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AnalyticsContainer = Depends(get_container),
) -> dict[str, Any]:
    from analytics.application._auth import require_at_least
    from analytics.domain.value_objects.enums import AnalyticsRole

    try:
        require_at_least(roles, AnalyticsRole.ADMIN)
        return await container.scheduler.daily_tick(tenant_id)
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/queries")
async def create_query(
    body: CreateQueryRequest,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AnalyticsContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.create_query(
            CreateAnalyticsQueryCommand(
                tenant_id,
                body.name,
                body.template,
                body.domain,
                tuple(body.parameters),
                body.created_by,
                roles,
            )
        )
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/queries/{query_id}/execute")
async def execute_query(
    query_id: UUID,
    body: ExecuteQueryRequest,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AnalyticsContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.execute_query(
            ExecuteAnalyticsQueryCommand(
                tenant_id, query_id, body.parameters, body.executed_by, roles
            )
        )
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/queries")
async def list_queries(
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AnalyticsContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    try:
        return await container.app.list_queries(tenant_id, roles)
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/query-results/{execution_id}")
async def get_result(
    execution_id: str,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AnalyticsContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.get_query_result(tenant_id, execution_id, roles)
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/datasets/{dataset_id}/export")
async def export_dataset(
    dataset_id: UUID,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=1000),
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AnalyticsContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.export_dataset(
            tenant_id, dataset_id, roles, page=page, page_size=page_size
        )
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/health")
async def health(
    container: AnalyticsContainer = Depends(get_container),
) -> dict[str, Any]:
    return {
        "status": "ok",
        "context": "analytics",
        "phase": 5,
        "scheduler_last_tick_at": container.scheduler.last_tick_at,
        "metrics": container.metrics.snapshot(),
        "dead_letter_count": len(container.projection_worker.dead_letters),
        "feature_flags": {
            "enable_ml_anomaly": container.settings.enable_ml_anomaly,
            "enable_graph_anomaly_writes": container.settings.enable_graph_anomaly_writes,
            "enable_iqr_rolling": container.settings.enable_iqr_rolling,
        },
    }
