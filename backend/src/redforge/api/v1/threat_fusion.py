"""Threat Fusion internal administration API — M22 Phase 4."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from redforge.api.security import PlatformContext, require_platform_permission
from redforge.application.threat_intel.threat_fusion_query_service import (
    ThreatFusionQueryService,
)
from redforge.application.threat_intel.threat_fusion_service import ThreatFusionService
from redforge.core.exceptions import NotFoundError
from redforge.domain.platform_identity.value_objects import PlatformPermission
from redforge.domain.threat_intel.fusion_value_objects import (
    FusedIndicatorType,
    IndicatorLifecycle,
)

router = APIRouter(prefix="/threat-intel/fusion", tags=["threat-fusion"])


def _session_factory() -> object:
    from redforge.api.dependencies import get_session_factory

    return get_session_factory()


class FusionRunResponse(BaseModel):
    indicators_created: int
    indicators_updated: int
    relationships_upserted: int
    stub_indicators_created: int
    no_evidence_count: int


class FusionWeightUpdate(BaseModel):
    source_system: str = Field(..., min_length=1, max_length=30)
    weight: float = Field(..., gt=0.0, le=1.0)


class IndicatorResponse(BaseModel):
    id: str
    canonical_key: str
    indicator_type: str
    display_name: str
    lifecycle: str
    confidence: str | None
    risk_state: str
    winner_source_system: str | None
    source_count: int
    metadata: dict[str, Any]
    valid_from: str
    valid_until: str | None


@router.post("/run", response_model=FusionRunResponse)
async def run_fusion(
    ctx: Annotated[
        PlatformContext,
        Depends(require_platform_permission(PlatformPermission.PLATFORM_THREAT_FUSION_MANAGE)),
    ],
) -> FusionRunResponse:
    service = ThreatFusionService(_session_factory())  # type: ignore[arg-type]
    result = await service.fuse_reference_catalog(actor_id=ctx.user_id)
    return FusionRunResponse(
        indicators_created=result.indicators_created,
        indicators_updated=result.indicators_updated,
        relationships_upserted=result.relationships_upserted,
        stub_indicators_created=result.stub_indicators_created,
        no_evidence_count=result.no_evidence_count,
    )


@router.get("/weights")
async def list_weights(
    _ctx: Annotated[
        PlatformContext,
        Depends(require_platform_permission(PlatformPermission.PLATFORM_THREAT_FUSION_READ)),
    ],
) -> dict[str, float]:
    service = ThreatFusionService(_session_factory())  # type: ignore[arg-type]
    return await service.list_effective_weights()


@router.put("/weights")
async def update_weight(
    body: FusionWeightUpdate,
    ctx: Annotated[
        PlatformContext,
        Depends(require_platform_permission(PlatformPermission.PLATFORM_THREAT_FUSION_MANAGE)),
    ],
) -> dict[str, float]:
    service = ThreatFusionService(_session_factory())  # type: ignore[arg-type]
    await service.update_fusion_weight(
        source_system=body.source_system, weight=body.weight, actor_id=ctx.user_id
    )
    return await service.list_effective_weights()


@router.get("/indicators", response_model=list[IndicatorResponse])
async def list_indicators(
    _ctx: Annotated[
        PlatformContext,
        Depends(require_platform_permission(PlatformPermission.PLATFORM_THREAT_FUSION_READ)),
    ],
    indicator_type: str = Query(..., min_length=1),
    lifecycle: str | None = Query(default="active"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[IndicatorResponse]:
    query = ThreatFusionQueryService(_session_factory())  # type: ignore[arg-type]
    life = IndicatorLifecycle(lifecycle) if lifecycle else None
    items = await query.list_indicators(
        FusedIndicatorType(indicator_type),
        lifecycle=life,
        limit=limit,
        offset=offset,
    )
    return [_to_response(i) for i in items]


@router.get("/indicators/{indicator_id}", response_model=IndicatorResponse)
async def get_indicator(
    indicator_id: str,
    _ctx: Annotated[
        PlatformContext,
        Depends(require_platform_permission(PlatformPermission.PLATFORM_THREAT_FUSION_READ)),
    ],
) -> IndicatorResponse:
    query = ThreatFusionQueryService(_session_factory())  # type: ignore[arg-type]
    item = await query.get_indicator(indicator_id)
    if item is None:
        raise NotFoundError("FusedIndicator", indicator_id)
    return _to_response(item)


def _to_response(item: object) -> IndicatorResponse:
    from redforge.domain.threat_intel.fusion_entity import FusedIndicator

    assert isinstance(item, FusedIndicator)
    return IndicatorResponse(
        id=item.id,
        canonical_key=item.canonical_key.value,
        indicator_type=item.indicator_type.value,
        display_name=item.display_name,
        lifecycle=item.lifecycle.value,
        confidence=item.confidence.value if item.confidence else None,
        risk_state=item.aggregated_risk.state.value,
        winner_source_system=item.aggregated_risk.winner_source_system,
        source_count=len(item.attributions),
        metadata=item.metadata,
        valid_from=item.temporal.valid_from.isoformat(),
        valid_until=(
            item.temporal.valid_until.isoformat() if item.temporal.valid_until else None
        ),
    )
