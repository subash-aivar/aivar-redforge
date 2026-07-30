"""Risk profile lifecycle + query API routers (M48F).

Endpoint set is bounded strictly by what
`EnterpriseRiskProfileApplicationService`/`RiskQueryService`/
`RiskTimelineApplicationService` actually expose — create, get, list,
recompute, acknowledge, mitigate, accept, close, and timeline. No
endpoint here invents a capability the frozen M48C/M48D application
layer does not already have.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime
from types import MappingProxyType
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from redforge.api.security import TenantContext, require_permission
from redforge.domain.identity.value_objects import Permission
from redforge.shared.identifiers import EntityId
from risk_engine.api.dependencies import (
    CorrelationServiceDep,
    ProfileServiceDep,
    QueryServiceDep,
    TenantIdDep,
    TimelineServiceDep,
)
from risk_engine.api.schemas.risk_schemas import (
    AcceptRiskProfileRequest,
    CreateRiskProfileRequest,
    EvaluateAcceptanceExpiryRequest,
    EvaluateEscalationRequest,
    ListRiskProfilesResponse,
    RecomputeRiskProfileRequest,
    RiskAcceptanceExpiryDecisionResponse,
    RiskEscalationDecisionResponse,
    RiskProfileResponse,
    RiskSignalReferenceRequest,
    RiskTimelineResponse,
)
from risk_engine.application.commands.risk_correlation_commands import (
    EvaluateRiskAcceptanceExpiryCommand,
    EvaluateRiskEscalationCommand,
)
from risk_engine.application.commands.risk_profile_commands import (
    AcceptEnterpriseRiskCommand,
    AcknowledgeEnterpriseRiskCommand,
    CloseEnterpriseRiskCommand,
    CreateEnterpriseRiskProfileCommand,
    MitigateEnterpriseRiskCommand,
    RecomputeEnterpriseRiskCommand,
    RiskDimensionSignal,
)
from risk_engine.application.dtos.risk_profile_dto import EnterpriseRiskProfileDTO
from risk_engine.application.queries.risk_profile_queries import (
    GetEnterpriseRiskProfileQuery,
    GetRiskTimelineQuery,
    ListEnterpriseRiskProfilesQuery,
)
from risk_engine.domain.value_objects.enums import (
    RiskDimension,
    RiskProfileStatus,
    RiskScale,
    RiskSignalType,
)
from risk_engine.domain.value_objects.identifiers import RiskProfileId
from risk_engine.domain.value_objects.normalized_score import NormalizedRiskScore
from risk_engine.domain.value_objects.risk_signal import RiskSignalReference
from risk_engine.domain.value_objects.weight_profile import RiskWeightProfile

risk_profiles_router = APIRouter()


def _signal_reference(body: RiskSignalReferenceRequest, tenant_id: EntityId) -> RiskSignalReference:
    try:
        return RiskSignalReference(
            tenant_id=tenant_id,
            source_context=body.source_context,
            source_aggregate_type=body.source_aggregate_type,
            source_id=body.source_id,
            signal_type=RiskSignalType(body.signal_type),
            raw_value=body.raw_value,
            raw_scale=RiskScale(body.raw_scale),
            observed_at=body.observed_at,
            subject_reference=body.subject_reference,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _profile_response(dto: EnterpriseRiskProfileDTO) -> RiskProfileResponse:
    return RiskProfileResponse.model_validate(asdict(dto))


@risk_profiles_router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=RiskProfileResponse,
    summary="Create an enterprise risk profile",
)
async def create_risk_profile(
    body: CreateRiskProfileRequest,
    response: Response,
    tenant_id: TenantIdDep,
    svc: ProfileServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_MANAGE)),
) -> RiskProfileResponse:
    try:
        dimension = RiskDimension(body.dimension)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    signal_reference = _signal_reference(body.signal_reference, tenant_id)
    dto = await svc.create_profile(
        CreateEnterpriseRiskProfileCommand(
            tenant_id=tenant_id,
            subject_reference=body.subject_reference,
            dimension=dimension,
            signal_reference=signal_reference,
            profile_id=RiskProfileId(UUID(body.profile_id)) if body.profile_id else None,
        )
    )
    response.headers["Location"] = f"/api/v1/risk-profiles/{dto.profile_id}"
    return _profile_response(dto)


@risk_profiles_router.get(
    "/{profile_id}",
    response_model=RiskProfileResponse,
    summary="Get an enterprise risk profile",
)
async def get_risk_profile(
    profile_id: UUID,
    tenant_id: TenantIdDep,
    svc: QueryServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_READ)),
) -> RiskProfileResponse:
    dto = await svc.get_profile(
        GetEnterpriseRiskProfileQuery(
            tenant_id=tenant_id,
            profile_id=RiskProfileId(profile_id),
        )
    )
    if dto is None:
        raise HTTPException(status_code=404, detail=f"No enterprise risk profile {profile_id}")
    return _profile_response(dto)


@risk_profiles_router.get(
    "",
    response_model=ListRiskProfilesResponse,
    summary="List enterprise risk profiles",
)
async def list_risk_profiles(
    tenant_id: TenantIdDep,
    svc: QueryServiceDep,
    profile_status: RiskProfileStatus | None = Query(default=None, alias="status"),
    subject_reference: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_READ)),
) -> ListRiskProfilesResponse:
    items = await svc.list_profiles(
        ListEnterpriseRiskProfilesQuery(
            tenant_id=tenant_id,
            status=profile_status,
            subject_reference=subject_reference,
        )
    )
    # `EnterpriseRiskProfileRepository.list` has no server-side
    # pagination in the frozen M48C/M48E port/repository — limit/offset
    # are applied here at the API boundary rather than adding
    # pagination to the frozen repository contract.
    page = items[offset : offset + limit]
    return ListRiskProfilesResponse(
        items=[_profile_response(i) for i in page],
        count=len(items),
    )


@risk_profiles_router.post(
    "/{profile_id}/recompute",
    response_model=RiskProfileResponse,
    summary="Recompute an enterprise risk profile's composite score",
)
async def recompute_risk_profile(
    profile_id: UUID,
    body: RecomputeRiskProfileRequest,
    tenant_id: TenantIdDep,
    svc: ProfileServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_MANAGE)),
) -> RiskProfileResponse:
    try:
        signals = tuple(
            RiskDimensionSignal(
                dimension=RiskDimension(item.dimension),
                signal_reference=_signal_reference(item.signal_reference, tenant_id),
            )
            for item in body.signals
        )
        weight_profile = RiskWeightProfile(
            profile_name=body.weight_profile.profile_name,
            version=body.weight_profile.version,
            weights=MappingProxyType(
                {RiskDimension(dim): weight for dim, weight in body.weight_profile.weights.items()}
            ),
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    dto = await svc.recompute_score(
        RecomputeEnterpriseRiskCommand(
            tenant_id=tenant_id,
            profile_id=RiskProfileId(profile_id),
            signals=signals,
            weight_profile=weight_profile,
        )
    )
    return _profile_response(dto)


@risk_profiles_router.post(
    "/{profile_id}/acknowledge",
    response_model=RiskProfileResponse,
    summary="Acknowledge an enterprise risk profile",
)
async def acknowledge_risk_profile(
    profile_id: UUID,
    tenant_id: TenantIdDep,
    svc: ProfileServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_MANAGE)),
) -> RiskProfileResponse:
    dto = await svc.acknowledge(
        AcknowledgeEnterpriseRiskCommand(
            tenant_id=tenant_id,
            profile_id=RiskProfileId(profile_id),
        )
    )
    return _profile_response(dto)


@risk_profiles_router.post(
    "/{profile_id}/mitigate",
    response_model=RiskProfileResponse,
    summary="Mark an enterprise risk profile as mitigated",
)
async def mitigate_risk_profile(
    profile_id: UUID,
    tenant_id: TenantIdDep,
    svc: ProfileServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_MANAGE)),
) -> RiskProfileResponse:
    dto = await svc.mitigate(
        MitigateEnterpriseRiskCommand(
            tenant_id=tenant_id,
            profile_id=RiskProfileId(profile_id),
        )
    )
    return _profile_response(dto)


@risk_profiles_router.post(
    "/{profile_id}/accept",
    response_model=RiskProfileResponse,
    summary="Accept an enterprise risk profile until it expires",
)
async def accept_risk_profile(
    profile_id: UUID,
    body: AcceptRiskProfileRequest,
    tenant_id: TenantIdDep,
    svc: ProfileServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_MANAGE)),
) -> RiskProfileResponse:
    dto = await svc.accept(
        AcceptEnterpriseRiskCommand(
            tenant_id=tenant_id,
            profile_id=RiskProfileId(profile_id),
            expires_at=body.expires_at,
        )
    )
    return _profile_response(dto)


@risk_profiles_router.post(
    "/{profile_id}/close",
    response_model=RiskProfileResponse,
    summary="Close an enterprise risk profile",
)
async def close_risk_profile(
    profile_id: UUID,
    tenant_id: TenantIdDep,
    svc: ProfileServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_MANAGE)),
) -> RiskProfileResponse:
    dto = await svc.close(
        CloseEnterpriseRiskCommand(
            tenant_id=tenant_id,
            profile_id=RiskProfileId(profile_id),
        )
    )
    return _profile_response(dto)


@risk_profiles_router.get(
    "/{profile_id}/timeline",
    response_model=RiskTimelineResponse,
    summary="Get an enterprise risk profile's composite-score timeline",
)
async def get_risk_profile_timeline(
    profile_id: UUID,
    tenant_id: TenantIdDep,
    svc: TimelineServiceDep,
    since: str | None = Query(default=None),
    until: str | None = Query(default=None),
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_READ)),
) -> RiskTimelineResponse:
    dto = await svc.get_timeline(
        GetRiskTimelineQuery(
            tenant_id=tenant_id,
            profile_id=RiskProfileId(profile_id),
            since=datetime.fromisoformat(since) if since else None,
            until=datetime.fromisoformat(until) if until else None,
        )
    )
    return RiskTimelineResponse.model_validate(asdict(dto))


@risk_profiles_router.post(
    "/{profile_id}/evaluate-escalation",
    response_model=RiskEscalationDecisionResponse,
    summary="Evaluate whether an enterprise risk profile should escalate",
)
async def evaluate_risk_escalation(
    profile_id: UUID,
    body: EvaluateEscalationRequest,
    tenant_id: TenantIdDep,
    svc: CorrelationServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_READ)),
) -> RiskEscalationDecisionResponse:
    dto = await svc.evaluate_escalation(
        EvaluateRiskEscalationCommand(
            tenant_id=tenant_id,
            profile_id=RiskProfileId(profile_id),
            critical_threshold=NormalizedRiskScore(body.critical_threshold),
        )
    )
    return RiskEscalationDecisionResponse.model_validate(asdict(dto))


@risk_profiles_router.post(
    "/{profile_id}/evaluate-acceptance-expiry",
    response_model=RiskAcceptanceExpiryDecisionResponse,
    summary="Evaluate whether an accepted enterprise risk profile's acceptance has expired",
)
async def evaluate_risk_acceptance_expiry(
    profile_id: UUID,
    body: EvaluateAcceptanceExpiryRequest,
    tenant_id: TenantIdDep,
    svc: CorrelationServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_MANAGE)),
) -> RiskAcceptanceExpiryDecisionResponse:
    dto = await svc.evaluate_acceptance_expiry(
        EvaluateRiskAcceptanceExpiryCommand(
            tenant_id=tenant_id,
            profile_id=RiskProfileId(profile_id),
            critical_threshold=NormalizedRiskScore(body.critical_threshold),
            now=datetime.now(UTC),
        )
    )
    return RiskAcceptanceExpiryDecisionResponse.model_validate(asdict(dto))
