from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from ml_pipeline.api.dependencies import get_actor_roles, get_container, get_tenant_id
from ml_pipeline.api.schemas.ml_schemas import (
    DeprecateRequest,
    DriftRequest,
    InferenceRequest,
    PromoteRequest,
    ScheduleTrainingRequest,
)
from ml_pipeline.application.commands.ml_commands import (
    DeprecateMLModelCommand,
    PromoteMLModelCommand,
    ScheduleMLModelTrainingCommand,
)
from ml_pipeline.application.exceptions import (
    ApplicationForbiddenError,
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from ml_pipeline.domain.exceptions.domain_exceptions import MLPipelineDomainError
from ml_pipeline.infrastructure.container import MLPipelineContainer

router = APIRouter(prefix="/ml-pipeline", tags=["ml-pipeline"])


def _map(exc: Exception) -> HTTPException:
    if isinstance(exc, ApplicationForbiddenError):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, ApplicationNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, (ApplicationValidationError, MLPipelineDomainError)):
        return HTTPException(status_code=400, detail=str(exc))
    return HTTPException(status_code=500, detail="Internal error")


@router.post("/models/train")
async def schedule_training(
    body: ScheduleTrainingRequest,
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: MLPipelineContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.schedule_training(
            ScheduleMLModelTrainingCommand(
                tenant_id,
                body.model_type,
                body.dataset_id,
                roles,
                tuple(body.training_rows),
            )
        )
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/models/{model_id}/promote")
async def promote(
    model_id: UUID,
    body: PromoteRequest,
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: MLPipelineContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.promote(
            PromoteMLModelCommand(tenant_id, model_id, body.deployed_by, roles)
        )
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/models/{model_id}/deprecate")
async def deprecate(
    model_id: UUID,
    body: DeprecateRequest,
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: MLPipelineContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.deprecate(
            DeprecateMLModelCommand(tenant_id, model_id, body.deprecated_by, roles)
        )
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/models/{model_id}")
async def get_model(
    model_id: UUID,
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: MLPipelineContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.get_model(tenant_id, model_id, roles)
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/models")
async def list_models(
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    model_type: str | None = None,
    status: str | None = None,
    container: MLPipelineContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    try:
        return await container.app.list_models(
            tenant_id, roles, model_type=model_type, status=status
        )
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/models/{model_id}/governance")
async def governance(
    model_id: UUID,
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: MLPipelineContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    try:
        return await container.app.governance_history(tenant_id, model_id, roles)
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/signals")
async def get_signals(
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    asset_ref_id: UUID | None = Query(default=None),
    signal_type: str | None = Query(default=None),
    container: MLPipelineContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.get_signals(
            tenant_id, roles, asset_ref_id=asset_ref_id, signal_type=signal_type
        )
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/inference")
async def inference(
    body: InferenceRequest,
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: MLPipelineContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.app.run_inference(tenant_id, body.model_type, body.assets, roles)
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/models/{model_id}/drift-check")
async def drift_check(
    model_id: UUID,
    body: DriftRequest,
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: MLPipelineContainer = Depends(get_container),
) -> dict[str, Any]:
    from ml_pipeline.application._auth import require_at_least
    from ml_pipeline.domain.value_objects.enums import AnalyticsRole

    try:
        require_at_least(roles, AnalyticsRole.ADMIN)
        return await container.app.check_drift(tenant_id, model_id, body.actual)
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "context": "ml_pipeline", "phase": 3}
