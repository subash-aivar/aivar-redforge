"""Adversary-Campaign Intelligence API router, mirroring
`malware_intel.api.v1.malware`'s exact ownership-based authorization
shape: `POST /observations/tenant` and `POST /observations/global`
remain two explicit routes (ownership must be stated up front — no
existing Campaign to load yet); `GET /` (tenant list) and `GET /global`
(global list) are unambiguous, non-duplicated paths; every
`{campaign_id}` operation is ONE canonical route, authorizing
dynamically from the *loaded Campaign's own ownership scope*
(`Campaign.tenant_id`, resolved via
`CampaignApplicationService.get_scope`) rather than from which URL
prefix the caller happened to use:

    scope = await svc.get_scope(campaign_id)   # TenantId | None; 404 if missing
    if scope is None:                          # global
        require platform.has_permission(...)   # else 403
    else:                                      # tenant-owned
        require tenant is not None and tenant.organization_id == str(scope)
                                                 # else 404 (cross-tenant)
        require tenant.has_permission(...)      # else 403

The URL prefix is `/campaign-intel` — deliberately distinct from any
route RedForge's own red-team campaign orchestration might claim, since
these are unrelated concepts.

`PATCH /{campaign_id}/transition-status` moves the REAL-WORLD campaign's
operational status; `deprecate`/`revoke`/`supersede`/`reactivate` move
RedForge's own RECORD lifecycle. Two independent axes, two distinct sets
of routes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, Query, Response, status

from campaign_intel.api.dependencies import (
    CampaignServiceDep,
    OptionalTenantContextDep,
    PlatformContextDep,
    TenantIdDep,
)
from campaign_intel.api.schemas.campaign_schemas import (
    AddAliasRequest,
    AddEvidenceCitationRequest,
    AddObjectiveRequest,
    AddRegionRequest,
    AddSourceAttributionRequest,
    AddTargetSectorRequest,
    CampaignDetailResponse,
    CampaignSummaryResponse,
    LifecycleTransitionRequest,
    ObjectiveRequest,
    ObjectiveResponse,
    ObserveCampaignRequest,
    PaginatedCampaignListResponse,
    SourceAttributionRequest,
    SourceAttributionResponse,
    SupersedeCampaignRequest,
    TimelineResponse,
    TransitionStatusRequest,
    VersionRecordResponse,
)
from campaign_intel.application.commands.campaign_commands import (
    AddAliasCommand,
    AddEvidenceCitationCommand,
    AddObjectiveCommand,
    AddRegionCommand,
    AddSourceAttributionCommand,
    AddTargetSectorCommand,
    DeprecateCampaignCommand,
    ObjectiveInput,
    ObserveCampaignCommand,
    ReactivateCampaignCommand,
    RevokeCampaignCommand,
    SourceAttributionInput,
    SupersedeCampaignCommand,
    TimelineInput,
    TransitionCampaignStatusCommand,
)
from campaign_intel.application.exceptions import (
    ApplicationForbiddenError,
    ApplicationNotFoundError,
)
from campaign_intel.application.queries.campaign_queries import (
    DEFAULT_LIST_LIMIT,
    MAX_LIST_LIMIT,
    GetCampaignQuery,
    ListCampaignsQuery,
)
from redforge.api.security import (
    TenantContext,
    require_permission,
    require_platform_permission,
)
from redforge.domain.identity.value_objects import Permission
from redforge.domain.platform_identity.value_objects import PlatformPermission

if TYPE_CHECKING:
    from campaign_intel.api.schemas.campaign_schemas import TimelineRequest
    from campaign_intel.application.dtos.campaign_dtos import (
        CampaignDetailDTO,
        CampaignSummaryDTO,
    )
    from campaign_intel.application.services.campaign_application_service import (
        CampaignApplicationService,
    )
    from campaign_intel.domain.value_objects.identifiers import TenantId
    from redforge.api.security import PlatformContext

campaign_router = APIRouter()


async def _authorize_scope(
    campaign_id: str,
    svc: CampaignApplicationService,
    tenant: TenantContext | None,
    platform: PlatformContext,
    *,
    tenant_permission: Permission,
    platform_permission: PlatformPermission,
) -> TenantId | None:
    """The single ownership-based authorization decision every canonical
    `{campaign_id}` route uses. Raises `ApplicationNotFoundError` (404)
    if the Campaign doesn't exist, `ApplicationForbiddenError` (403) if
    the caller lacks the required authority for the resource's actual
    scope, or returns the `tenant_id` to use for the real, authorized
    operation (`None` for global)."""
    scope = await svc.get_scope(campaign_id)
    if scope is None:
        if not platform.has_permission(platform_permission):
            raise ApplicationForbiddenError(platform_permission.value)
        return None
    if tenant is None or tenant.organization_id != str(scope):
        raise ApplicationNotFoundError("Campaign", campaign_id)
    if not tenant.has_permission(tenant_permission):
        raise ApplicationForbiddenError(tenant_permission.value)
    return scope


def _to_attribution_input(attribution: SourceAttributionRequest) -> SourceAttributionInput:
    return SourceAttributionInput(
        source_system=attribution.source_system,
        reference=attribution.reference,
        observed_at=attribution.observed_at,
        confidence=attribution.confidence,
        notes=attribution.notes,
    )


def _to_objective_input(objective: ObjectiveRequest) -> ObjectiveInput:
    return ObjectiveInput(
        objective_type=objective.objective_type, description=objective.description
    )


def _to_timeline_input(timeline: TimelineRequest | None) -> TimelineInput | None:
    if timeline is None:
        return None
    return TimelineInput(
        first_observed=timeline.first_observed,
        last_observed=timeline.last_observed,
        ongoing=timeline.ongoing,
    )


def _detail_response(dto: CampaignDetailDTO) -> CampaignDetailResponse:
    return CampaignDetailResponse(
        campaign_id=dto.campaign_id,
        tenant_id=dto.tenant_id,
        canonical_name=dto.canonical_name,
        status=dto.status,
        lifecycle_status=dto.lifecycle_status,
        motivation=dto.motivation,
        confidence=dto.confidence,
        superseded_by=dto.superseded_by,
        created_at=dto.created_at,
        updated_at=dto.updated_at,
        timeline=(
            TimelineResponse(
                first_observed=dto.timeline.first_observed,
                last_observed=dto.timeline.last_observed,
                ongoing=dto.timeline.ongoing,
            )
            if dto.timeline is not None
            else None
        ),
        aliases=list(dto.aliases),
        objectives=[
            ObjectiveResponse(objective_type=o.objective_type, description=o.description)
            for o in dto.objectives
        ],
        regions=list(dto.regions),
        target_sectors=list(dto.target_sectors),
        evidence_citations=list(dto.evidence_citations),
        source_attributions=[
            SourceAttributionResponse(
                source_system=a.source_system,
                reference=a.reference,
                observed_at=a.observed_at,
                confidence=a.confidence,
                notes=a.notes,
            )
            for a in dto.source_attributions
        ],
        version_history=[
            VersionRecordResponse(
                version=v.version,
                changed_at=v.changed_at,
                change_summary=v.change_summary,
                source=v.source,
            )
            for v in dto.version_history
        ],
    )


def _summary_response(dto: CampaignSummaryDTO) -> CampaignSummaryResponse:
    return CampaignSummaryResponse(
        campaign_id=dto.campaign_id,
        tenant_id=dto.tenant_id,
        canonical_name=dto.canonical_name,
        status=dto.status,
        lifecycle_status=dto.lifecycle_status,
        motivation=dto.motivation,
        confidence=dto.confidence,
        created_at=dto.created_at,
        updated_at=dto.updated_at,
        alias_count=dto.alias_count,
        objective_count=dto.objective_count,
        region_count=dto.region_count,
        target_sector_count=dto.target_sector_count,
    )


def _observe_command(
    body: ObserveCampaignRequest, tenant_id: TenantId | None
) -> ObserveCampaignCommand:
    return ObserveCampaignCommand(
        tenant_id=tenant_id,
        canonical_name=body.canonical_name,
        status=body.status,
        motivation=body.motivation,
        confidence=body.confidence,
        timeline=_to_timeline_input(body.timeline),
        aliases=tuple(body.aliases),
        objectives=tuple(_to_objective_input(o) for o in body.objectives),
        regions=tuple(body.regions),
        target_sectors=tuple(body.target_sectors),
    )


# ── Observation (ownership stated explicitly — no existing Campaign) ────


@campaign_router.post(
    "/observations/tenant",
    status_code=status.HTTP_201_CREATED,
    response_model=CampaignDetailResponse,
    summary="Observe a tenant-scoped adversary Campaign",
    description=(
        "Tenant-scoped adversary-campaign observation. `canonical_name` "
        "is strongly normalized and deduplicated within this tenant's "
        "scope — never creates a second identity for the same normalized "
        "name."
    ),
)
async def observe_tenant_campaign(
    body: ObserveCampaignRequest,
    response: Response,
    tenant_id: TenantIdDep,
    svc: CampaignServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.CAMPAIGN_OBSERVE)),
) -> CampaignDetailResponse:
    dto = await svc.observe(_observe_command(body, tenant_id))
    response.headers["Location"] = f"/api/v1/campaign-intel/{dto.campaign_id}"
    return _detail_response(dto)


@campaign_router.post(
    "/observations/global",
    status_code=status.HTTP_201_CREATED,
    response_model=CampaignDetailResponse,
    summary="Observe a global adversary Campaign (platform authority required)",
    description=(
        "Global, RedForge-curated adversary Campaign. Requires platform "
        "authority (PLATFORM_CAMPAIGN_MANAGE) — no organization OWNER/"
        "ADMIN/SECURITY_MANAGER membership satisfies this."
    ),
)
async def observe_global_campaign(
    body: ObserveCampaignRequest,
    response: Response,
    svc: CampaignServiceDep,
    _platform: PlatformContext = Depends(
        require_platform_permission(PlatformPermission.PLATFORM_CAMPAIGN_MANAGE)
    ),
) -> CampaignDetailResponse:
    dto = await svc.observe(_observe_command(body, None))
    response.headers["Location"] = f"/api/v1/campaign-intel/{dto.campaign_id}"
    return _detail_response(dto)


# ── Lists (unambiguous, distinct paths) ─────────────────────────────────


@campaign_router.get(
    "",
    response_model=PaginatedCampaignListResponse,
    summary="List this tenant's adversary Campaign records",
)
async def list_tenant_campaigns(
    tenant_id: TenantIdDep,
    svc: CampaignServiceDep,
    lifecycle_status: str | None = Query(default=None),
    campaign_status: str | None = Query(default=None, alias="status"),
    motivation: str | None = Query(default=None),
    target_sector: str | None = Query(default=None),
    limit: int = Query(default=DEFAULT_LIST_LIMIT, ge=1, le=MAX_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
    _tenant: TenantContext = Depends(require_permission(Permission.CAMPAIGN_READ)),
) -> PaginatedCampaignListResponse:
    items = await svc.list(
        ListCampaignsQuery(
            tenant_id=tenant_id,
            lifecycle_status=lifecycle_status,
            status=campaign_status,
            motivation=motivation,
            target_sector=target_sector,
            limit=limit,
            offset=offset,
        )
    )
    summaries = [_summary_response(i) for i in items]
    return PaginatedCampaignListResponse(
        items=summaries, count=len(summaries), limit=limit, offset=offset
    )


@campaign_router.get(
    "/global",
    response_model=PaginatedCampaignListResponse,
    summary="List global adversary Campaign records",
)
async def list_global_campaigns(
    svc: CampaignServiceDep,
    lifecycle_status: str | None = Query(default=None),
    campaign_status: str | None = Query(default=None, alias="status"),
    motivation: str | None = Query(default=None),
    target_sector: str | None = Query(default=None),
    limit: int = Query(default=DEFAULT_LIST_LIMIT, ge=1, le=MAX_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
    _platform: PlatformContext = Depends(
        require_platform_permission(PlatformPermission.PLATFORM_CAMPAIGN_READ)
    ),
) -> PaginatedCampaignListResponse:
    items = await svc.list(
        ListCampaignsQuery(
            tenant_id=None,
            lifecycle_status=lifecycle_status,
            status=campaign_status,
            motivation=motivation,
            target_sector=target_sector,
            limit=limit,
            offset=offset,
        )
    )
    summaries = [_summary_response(i) for i in items]
    return PaginatedCampaignListResponse(
        items=summaries, count=len(summaries), limit=limit, offset=offset
    )


# ── Canonical single routes per {campaign_id} operation ────────────────


@campaign_router.get(
    "/{campaign_id}",
    response_model=CampaignDetailResponse,
    summary="Get an adversary Campaign record",
)
async def get_campaign(
    campaign_id: str,
    svc: CampaignServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> CampaignDetailResponse:
    tenant_id = await _authorize_scope(
        campaign_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.CAMPAIGN_READ,
        platform_permission=PlatformPermission.PLATFORM_CAMPAIGN_READ,
    )
    dto = await svc.get(GetCampaignQuery(tenant_id=tenant_id, campaign_id=campaign_id))
    return _detail_response(dto)


@campaign_router.post(
    "/{campaign_id}/aliases",
    response_model=CampaignDetailResponse,
    summary="Add an alias",
)
async def add_alias(
    campaign_id: str,
    body: AddAliasRequest,
    svc: CampaignServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> CampaignDetailResponse:
    tenant_id = await _authorize_scope(
        campaign_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.CAMPAIGN_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_CAMPAIGN_MANAGE,
    )
    dto = await svc.add_alias(
        AddAliasCommand(tenant_id=tenant_id, campaign_id=campaign_id, alias=body.alias)
    )
    return _detail_response(dto)


@campaign_router.post(
    "/{campaign_id}/objectives",
    response_model=CampaignDetailResponse,
    summary="Add an assessed objective",
)
async def add_objective(
    campaign_id: str,
    body: AddObjectiveRequest,
    svc: CampaignServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> CampaignDetailResponse:
    tenant_id = await _authorize_scope(
        campaign_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.CAMPAIGN_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_CAMPAIGN_MANAGE,
    )
    dto = await svc.add_objective(
        AddObjectiveCommand(
            tenant_id=tenant_id,
            campaign_id=campaign_id,
            objective=_to_objective_input(body.objective),
        )
    )
    return _detail_response(dto)


@campaign_router.post(
    "/{campaign_id}/regions",
    response_model=CampaignDetailResponse,
    summary="Add a targeted region",
)
async def add_region(
    campaign_id: str,
    body: AddRegionRequest,
    svc: CampaignServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> CampaignDetailResponse:
    tenant_id = await _authorize_scope(
        campaign_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.CAMPAIGN_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_CAMPAIGN_MANAGE,
    )
    dto = await svc.add_region(
        AddRegionCommand(tenant_id=tenant_id, campaign_id=campaign_id, region=body.region)
    )
    return _detail_response(dto)


@campaign_router.post(
    "/{campaign_id}/target-sectors",
    response_model=CampaignDetailResponse,
    summary="Add a targeted sector",
)
async def add_target_sector(
    campaign_id: str,
    body: AddTargetSectorRequest,
    svc: CampaignServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> CampaignDetailResponse:
    tenant_id = await _authorize_scope(
        campaign_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.CAMPAIGN_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_CAMPAIGN_MANAGE,
    )
    dto = await svc.add_target_sector(
        AddTargetSectorCommand(
            tenant_id=tenant_id, campaign_id=campaign_id, target_sector=body.target_sector
        )
    )
    return _detail_response(dto)


@campaign_router.post(
    "/{campaign_id}/evidence-citations",
    response_model=CampaignDetailResponse,
    summary="Add an evidence citation",
)
async def add_evidence_citation(
    campaign_id: str,
    body: AddEvidenceCitationRequest,
    svc: CampaignServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> CampaignDetailResponse:
    tenant_id = await _authorize_scope(
        campaign_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.CAMPAIGN_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_CAMPAIGN_MANAGE,
    )
    dto = await svc.add_evidence_citation(
        AddEvidenceCitationCommand(
            tenant_id=tenant_id, campaign_id=campaign_id, citation=body.citation
        )
    )
    return _detail_response(dto)


@campaign_router.post(
    "/{campaign_id}/source-attributions",
    response_model=CampaignDetailResponse,
    summary="Add a source attribution",
)
async def add_source_attribution(
    campaign_id: str,
    body: AddSourceAttributionRequest,
    svc: CampaignServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> CampaignDetailResponse:
    tenant_id = await _authorize_scope(
        campaign_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.CAMPAIGN_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_CAMPAIGN_MANAGE,
    )
    dto = await svc.add_source_attribution(
        AddSourceAttributionCommand(
            tenant_id=tenant_id,
            campaign_id=campaign_id,
            attribution=_to_attribution_input(body.attribution),
        )
    )
    return _detail_response(dto)


@campaign_router.patch(
    "/{campaign_id}/transition-status",
    response_model=CampaignDetailResponse,
    summary="Transition the REAL-WORLD campaign's operational status",
)
async def transition_campaign_status(
    campaign_id: str,
    body: TransitionStatusRequest,
    svc: CampaignServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> CampaignDetailResponse:
    tenant_id = await _authorize_scope(
        campaign_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.CAMPAIGN_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_CAMPAIGN_MANAGE,
    )
    dto = await svc.transition_status(
        TransitionCampaignStatusCommand(
            tenant_id=tenant_id,
            campaign_id=campaign_id,
            target_status=body.target_status,
            evidence=_to_attribution_input(body.evidence),
        )
    )
    return _detail_response(dto)


@campaign_router.patch(
    "/{campaign_id}/deprecate",
    response_model=CampaignDetailResponse,
    summary="Deprecate a Campaign RECORD",
)
async def deprecate_campaign(
    campaign_id: str,
    body: LifecycleTransitionRequest,
    svc: CampaignServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> CampaignDetailResponse:
    tenant_id = await _authorize_scope(
        campaign_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.CAMPAIGN_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_CAMPAIGN_MANAGE,
    )
    dto = await svc.deprecate(
        DeprecateCampaignCommand(
            tenant_id=tenant_id,
            campaign_id=campaign_id,
            evidence=_to_attribution_input(body.evidence),
        )
    )
    return _detail_response(dto)


@campaign_router.patch(
    "/{campaign_id}/revoke",
    response_model=CampaignDetailResponse,
    summary="Revoke a Campaign RECORD",
)
async def revoke_campaign(
    campaign_id: str,
    body: LifecycleTransitionRequest,
    svc: CampaignServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> CampaignDetailResponse:
    tenant_id = await _authorize_scope(
        campaign_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.CAMPAIGN_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_CAMPAIGN_MANAGE,
    )
    dto = await svc.revoke(
        RevokeCampaignCommand(
            tenant_id=tenant_id,
            campaign_id=campaign_id,
            evidence=_to_attribution_input(body.evidence),
        )
    )
    return _detail_response(dto)


@campaign_router.patch(
    "/{campaign_id}/supersede",
    response_model=CampaignDetailResponse,
    summary="Supersede a Campaign RECORD",
)
async def supersede_campaign(
    campaign_id: str,
    body: SupersedeCampaignRequest,
    svc: CampaignServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> CampaignDetailResponse:
    tenant_id = await _authorize_scope(
        campaign_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.CAMPAIGN_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_CAMPAIGN_MANAGE,
    )
    dto = await svc.supersede(
        SupersedeCampaignCommand(
            tenant_id=tenant_id,
            campaign_id=campaign_id,
            superseded_by=body.superseded_by,
            evidence=_to_attribution_input(body.evidence),
        )
    )
    return _detail_response(dto)


@campaign_router.patch(
    "/{campaign_id}/reactivate",
    response_model=CampaignDetailResponse,
    summary="Reactivate a Campaign RECORD",
)
async def reactivate_campaign(
    campaign_id: str,
    body: LifecycleTransitionRequest,
    svc: CampaignServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> CampaignDetailResponse:
    tenant_id = await _authorize_scope(
        campaign_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.CAMPAIGN_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_CAMPAIGN_MANAGE,
    )
    dto = await svc.reactivate(
        ReactivateCampaignCommand(
            tenant_id=tenant_id,
            campaign_id=campaign_id,
            evidence=_to_attribution_input(body.evidence),
        )
    )
    return _detail_response(dto)
