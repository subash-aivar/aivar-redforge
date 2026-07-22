from __future__ import annotations

from dataclasses import asdict
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from posture_forecasting.api.dependencies import get_container, roles_header, tenant_id_header
from posture_forecasting.application.commands.forecast_commands import GeneratePostureForecast
from posture_forecasting.application.exceptions import (
    ApplicationForbiddenError,
    ApplicationNotFoundError,
)
from posture_forecasting.domain.exceptions.domain_exceptions import PostureForecastingDomainError
from posture_forecasting.infrastructure.container import PostureForecastingContainer

router = APIRouter(prefix="/posture-forecasting", tags=["posture-forecasting"])


def _map(exc: Exception) -> HTTPException:
    if isinstance(exc, ApplicationForbiddenError):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, ApplicationNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, PostureForecastingDomainError):
        return HTTPException(status_code=409, detail=str(exc))
    return HTTPException(status_code=400, detail=str(exc))


class GenerateBody(BaseModel):
    baseline_exposure_score: float
    remediation_velocity_per_day: float = 1.0
    open_critical_count: int = 0
    open_high_count: int = 0


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "context": "posture_forecasting"}


@router.post("/forecasts", status_code=201)
async def generate(
    body: GenerateBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: PostureForecastingContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.generate(
            GeneratePostureForecast(
                tenant_id,
                body.baseline_exposure_score,
                body.remediation_velocity_per_day,
                body.open_critical_count,
                body.open_high_count,
                roles,
            )
        )
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/forecasts/latest")
async def latest(
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: PostureForecastingContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return asdict(await container.app.get_latest(tenant_id, roles))
    except Exception as exc:
        raise _map(exc) from exc
