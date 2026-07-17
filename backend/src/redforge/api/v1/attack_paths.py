"""Attack Path Engine internal administration API — M22 Phase 5."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from redforge.api.security import PlatformContext, require_platform_permission
from redforge.application.attack_path.attack_path_service import (
    AttackPathQueryService,
    AttackPathService,
)
from redforge.core.exceptions import NotFoundError
from redforge.domain.attack_path.value_objects import PathConfidence, PathStatus
from redforge.domain.platform_identity.value_objects import PlatformPermission

router = APIRouter(prefix="/attack-paths", tags=["attack-paths"])


def _session_factory() -> object:
    from redforge.api.dependencies import get_session_factory

    return get_session_factory()


class ComputeRequest(BaseModel):
    organization_id: str = Field(..., min_length=26, max_length=26)
    seed_indicator_id: str = Field(..., min_length=26, max_length=26)


class StepResponse(BaseModel):
    sequence: int
    entity_id: str
    canonical_key: str
    step_type: str
    confidence: str
    technique_id: str | None
    evidence_refs: list[str]
    relationship_type: str | None
    kill_chain_phase: str | None
    inferred_from_step: int | None
    exposure_score: float


class PathResponse(BaseModel):
    id: str
    organization_id: str
    root_entity_id: str
    root_canonical_key: str
    terminal_entity_id: str | None
    path_confidence: str
    technique_coverage: list[str]
    attributed_actors: list[str]
    step_count: int
    evidence_count: int
    max_exposure_score: float
    status: str
    steps: list[StepResponse] | None = None
    alternate_path_count: int | None = None


@router.post("/compute", response_model=PathResponse)
async def compute_path(
    body: ComputeRequest,
    ctx: Annotated[
        PlatformContext,
        Depends(require_platform_permission(PlatformPermission.PLATFORM_ATTACK_PATH_MANAGE)),
    ],
) -> PathResponse:
    service = AttackPathService(_session_factory())  # type: ignore[arg-type]
    result = await service.compute(
        organization_id=body.organization_id,
        seed_indicator_id=body.seed_indicator_id,
        actor_id=ctx.user_id,
    )
    return _path_response(result.path, list(result.steps), result.alternate_path_count)


@router.get("", response_model=list[PathResponse])
async def list_paths(
    _ctx: Annotated[
        PlatformContext,
        Depends(require_platform_permission(PlatformPermission.PLATFORM_ATTACK_PATH_READ)),
    ],
    organization_id: str = Query(..., min_length=26, max_length=26),
    status: str | None = Query(default=None),
    root_technique_id: str | None = Query(default=None),
    confidence_floor: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> list[PathResponse]:
    query = AttackPathQueryService(_session_factory())  # type: ignore[arg-type]
    paths = await query.list_paths(
        organization_id=organization_id,
        status=PathStatus(status) if status else None,
        root_technique_id=root_technique_id,
        confidence_floor=PathConfidence(confidence_floor) if confidence_floor else None,
        limit=limit,
        offset=offset,
    )
    return [_path_response(p) for p in paths]


@router.get("/{path_id}", response_model=PathResponse)
async def get_path(
    path_id: str,
    _ctx: Annotated[
        PlatformContext,
        Depends(require_platform_permission(PlatformPermission.PLATFORM_ATTACK_PATH_READ)),
    ],
    organization_id: str = Query(..., min_length=26, max_length=26),
) -> PathResponse:
    query = AttackPathQueryService(_session_factory())  # type: ignore[arg-type]
    result = await query.get_path(organization_id=organization_id, path_id=path_id)
    if result is None:
        raise NotFoundError("AttackPath", path_id)
    path, steps = result
    return _path_response(path, steps)


@router.post("/{path_id}/contain", response_model=PathResponse)
async def contain_path(
    path_id: str,
    ctx: Annotated[
        PlatformContext,
        Depends(require_platform_permission(PlatformPermission.PLATFORM_ATTACK_PATH_MANAGE)),
    ],
    organization_id: str = Query(..., min_length=26, max_length=26),
) -> PathResponse:
    service = AttackPathService(_session_factory())  # type: ignore[arg-type]
    path = await service.contain(
        organization_id=organization_id, path_id=path_id, actor_id=ctx.user_id
    )
    return _path_response(path)


@router.post("/{path_id}/archive", response_model=PathResponse)
async def archive_path(
    path_id: str,
    ctx: Annotated[
        PlatformContext,
        Depends(require_platform_permission(PlatformPermission.PLATFORM_ATTACK_PATH_MANAGE)),
    ],
    organization_id: str = Query(..., min_length=26, max_length=26),
) -> PathResponse:
    service = AttackPathService(_session_factory())  # type: ignore[arg-type]
    path = await service.archive(
        organization_id=organization_id, path_id=path_id, actor_id=ctx.user_id
    )
    return _path_response(path)


def _path_response(
    path: object,
    steps: list[Any] | None = None,
    alternate_path_count: int | None = None,
) -> PathResponse:
    from redforge.domain.attack_path.entity import AttackPath
    from redforge.domain.attack_path.value_objects import AttackStep

    assert isinstance(path, AttackPath)
    step_payload = None
    if steps is not None:
        step_payload = []
        for s in steps:
            assert isinstance(s, AttackStep)
            step_payload.append(
                StepResponse(
                    sequence=s.sequence,
                    entity_id=s.entity_id,
                    canonical_key=s.canonical_key,
                    step_type=s.step_type.value,
                    confidence=s.confidence.value,
                    technique_id=s.technique_id,
                    evidence_refs=list(s.evidence_refs),
                    relationship_type=s.relationship_type,
                    kill_chain_phase=s.kill_chain_phase,
                    inferred_from_step=s.inferred_from_step,
                    exposure_score=s.exposure_score,
                )
            )
    return PathResponse(
        id=path.id,
        organization_id=path.organization_id,
        root_entity_id=path.root_entity_id,
        root_canonical_key=path.root_canonical_key,
        terminal_entity_id=path.terminal_entity_id,
        path_confidence=path.path_confidence.value,
        technique_coverage=list(path.technique_coverage),
        attributed_actors=list(path.attributed_actors),
        step_count=path.step_count,
        evidence_count=path.evidence_count,
        max_exposure_score=path.max_exposure_score,
        status=path.status.value,
        steps=step_payload,
        alternate_path_count=alternate_path_count,
    )
