"""Adversary-Infrastructure Intelligence API router, mirroring
`tool_intel.api.v1.tools`'s exact ownership-based authorization shape:
`POST /observations/tenant` and `POST /observations/global` remain two
explicit routes (ownership must be stated up front — no existing
Infrastructure record to load yet); `GET /` (tenant list) and
`GET /global` (global list) are unambiguous, non-duplicated paths; every
`{infrastructure_id}` operation is ONE canonical route, authorizing
dynamically from the *loaded record's own ownership scope*
(`Infrastructure.tenant_id`, resolved via
`InfrastructureApplicationService.get_scope`) rather than from which URL
prefix the caller happened to use:

    scope = await svc.get_scope(infrastructure_id)  # TenantId|None; 404
    if scope is None:                      # global
        require platform.has_permission(...)   # else 403
    else:                                  # tenant-owned
        require tenant is not None and tenant.organization_id == str(scope)
                                                 # else 404 (cross-tenant)
        require tenant.has_permission(...)      # else 403

The URL prefix is `/infrastructure-intel` — deliberately distinct from
anything `attack_surface_management` or `cloud_security` might claim,
since RedForge's own discovered attack surface and its own cloud
account registrations are unrelated concepts that merely share the
English word "infrastructure".

`deprecate`/`revoke`/`supersede`/`reactivate` move RedForge's own RECORD
lifecycle — never a claim about the real-world infrastructure's
continued operation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, Query, Response, status

from infrastructure_intel.api.dependencies import (
    InfrastructureServiceDep,
    OptionalTenantContextDep,
    PlatformContextDep,
    TenantIdDep,
)
from infrastructure_intel.api.schemas.infrastructure_schemas import (
    AddEvidenceCitationRequest,
    AddRegionRequest,
    AddSourceAttributionRequest,
    InfrastructureDetailResponse,
    InfrastructureSummaryResponse,
    LifecycleTransitionRequest,
    NetworkOwnershipRequest,
    NetworkOwnershipResponse,
    ObserveInfrastructureRequest,
    PaginatedInfrastructureListResponse,
    SetCloudProviderRequest,
    SetHostingProviderRequest,
    SetNetworkOwnershipRequest,
    SourceAttributionRequest,
    SourceAttributionResponse,
    SupersedeInfrastructureRequest,
    VersionRecordResponse,
)
from infrastructure_intel.application.commands.infrastructure_commands import (
    AddEvidenceCitationCommand,
    AddRegionCommand,
    AddSourceAttributionCommand,
    DeprecateInfrastructureCommand,
    NetworkOwnershipInput,
    ObserveInfrastructureCommand,
    ReactivateInfrastructureCommand,
    RevokeInfrastructureCommand,
    SetCloudProviderCommand,
    SetHostingProviderCommand,
    SetNetworkOwnershipCommand,
    SourceAttributionInput,
    SupersedeInfrastructureCommand,
)
from infrastructure_intel.application.exceptions import (
    ApplicationForbiddenError,
    ApplicationNotFoundError,
)
from infrastructure_intel.application.queries.infrastructure_queries import (
    DEFAULT_LIST_LIMIT,
    MAX_LIST_LIMIT,
    GetInfrastructureQuery,
    ListInfrastructureQuery,
)
from redforge.api.security import (
    TenantContext,
    require_permission,
    require_platform_permission,
)
from redforge.domain.identity.value_objects import Permission
from redforge.domain.platform_identity.value_objects import PlatformPermission

if TYPE_CHECKING:
    from infrastructure_intel.application.dtos.infrastructure_dtos import (
        InfrastructureDetailDTO,
        InfrastructureSummaryDTO,
    )
    from infrastructure_intel.application.services.infrastructure_application_service import (
        InfrastructureApplicationService,
    )
    from infrastructure_intel.domain.value_objects.identifiers import TenantId
    from redforge.api.security import PlatformContext

infrastructure_router = APIRouter()


async def _authorize_scope(
    infrastructure_id: str,
    svc: InfrastructureApplicationService,
    tenant: TenantContext | None,
    platform: PlatformContext,
    *,
    tenant_permission: Permission,
    platform_permission: PlatformPermission,
) -> TenantId | None:
    """The single ownership-based authorization decision every canonical
    `{infrastructure_id}` route uses. Raises `ApplicationNotFoundError`
    (404) if the record doesn't exist, `ApplicationForbiddenError` (403)
    if the caller lacks the required authority for the resource's actual
    scope, or returns the `tenant_id` to use for the real, authorized
    operation (`None` for global)."""
    scope = await svc.get_scope(infrastructure_id)
    if scope is None:
        if not platform.has_permission(platform_permission):
            raise ApplicationForbiddenError(platform_permission.value)
        return None
    if tenant is None or tenant.organization_id != str(scope):
        raise ApplicationNotFoundError("Infrastructure", infrastructure_id)
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


def _to_ownership_input(ownership: NetworkOwnershipRequest) -> NetworkOwnershipInput:
    return NetworkOwnershipInput(
        registrant_organization=ownership.registrant_organization,
        abuse_contact=ownership.abuse_contact,
        notes=ownership.notes,
    )


def _detail_response(dto: InfrastructureDetailDTO) -> InfrastructureDetailResponse:
    return InfrastructureDetailResponse(
        infrastructure_id=dto.infrastructure_id,
        tenant_id=dto.tenant_id,
        infrastructure_type=dto.infrastructure_type,
        normalized_identifier=dto.normalized_identifier,
        lifecycle_status=dto.lifecycle_status,
        hosting_provider=dto.hosting_provider,
        cloud_provider=dto.cloud_provider,
        network_ownership=(
            NetworkOwnershipResponse(
                registrant_organization=dto.network_ownership.registrant_organization,
                abuse_contact=dto.network_ownership.abuse_contact,
                notes=dto.network_ownership.notes,
            )
            if dto.network_ownership is not None
            else None
        ),
        confidence=dto.confidence,
        superseded_by=dto.superseded_by,
        created_at=dto.created_at,
        updated_at=dto.updated_at,
        regions=list(dto.regions),
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


def _summary_response(dto: InfrastructureSummaryDTO) -> InfrastructureSummaryResponse:
    return InfrastructureSummaryResponse(
        infrastructure_id=dto.infrastructure_id,
        tenant_id=dto.tenant_id,
        infrastructure_type=dto.infrastructure_type,
        normalized_identifier=dto.normalized_identifier,
        lifecycle_status=dto.lifecycle_status,
        hosting_provider=dto.hosting_provider,
        cloud_provider=dto.cloud_provider,
        confidence=dto.confidence,
        created_at=dto.created_at,
        updated_at=dto.updated_at,
        region_count=dto.region_count,
        evidence_citation_count=dto.evidence_citation_count,
        source_attribution_count=dto.source_attribution_count,
    )


def _observe_command(
    body: ObserveInfrastructureRequest, tenant_id: TenantId | None
) -> ObserveInfrastructureCommand:
    return ObserveInfrastructureCommand(
        tenant_id=tenant_id,
        infrastructure_type=body.infrastructure_type,
        normalized_identifier=body.normalized_identifier,
        confidence=body.confidence,
        hosting_provider=body.hosting_provider,
        cloud_provider=body.cloud_provider,
        regions=tuple(body.regions),
        network_ownership=(
            _to_ownership_input(body.network_ownership)
            if body.network_ownership is not None
            else None
        ),
    )


# ── Observation (ownership stated explicitly — no existing record) ──────


@infrastructure_router.post(
    "/observations/tenant",
    status_code=status.HTTP_201_CREATED,
    response_model=InfrastructureDetailResponse,
    summary="Observe a tenant-scoped adversary Infrastructure footprint",
    description=(
        "Tenant-scoped adversary-infrastructure observation. "
        "`normalized_identifier` is strongly normalized per "
        "`infrastructure_type` and deduplicated within this tenant's "
        "scope — never creates a second identity for the same "
        "normalized (type, identifier) pair."
    ),
)
async def observe_tenant_infrastructure(
    body: ObserveInfrastructureRequest,
    response: Response,
    tenant_id: TenantIdDep,
    svc: InfrastructureServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.INFRASTRUCTURE_OBSERVE)),
) -> InfrastructureDetailResponse:
    dto = await svc.observe(_observe_command(body, tenant_id))
    response.headers["Location"] = f"/api/v1/infrastructure-intel/{dto.infrastructure_id}"
    return _detail_response(dto)


@infrastructure_router.post(
    "/observations/global",
    status_code=status.HTTP_201_CREATED,
    response_model=InfrastructureDetailResponse,
    summary="Observe a global adversary Infrastructure footprint (platform authority required)",
    description=(
        "Global, RedForge-curated adversary Infrastructure record. "
        "Requires platform authority (PLATFORM_INFRASTRUCTURE_MANAGE) — "
        "no organization OWNER/ADMIN/SECURITY_MANAGER membership "
        "satisfies this."
    ),
)
async def observe_global_infrastructure(
    body: ObserveInfrastructureRequest,
    response: Response,
    svc: InfrastructureServiceDep,
    _platform: PlatformContext = Depends(
        require_platform_permission(PlatformPermission.PLATFORM_INFRASTRUCTURE_MANAGE)
    ),
) -> InfrastructureDetailResponse:
    dto = await svc.observe(_observe_command(body, None))
    response.headers["Location"] = f"/api/v1/infrastructure-intel/{dto.infrastructure_id}"
    return _detail_response(dto)


# ── Lists (unambiguous, distinct paths) ─────────────────────────────────


@infrastructure_router.get(
    "",
    response_model=PaginatedInfrastructureListResponse,
    summary="List this tenant's adversary Infrastructure records",
)
async def list_tenant_infrastructure(
    tenant_id: TenantIdDep,
    svc: InfrastructureServiceDep,
    lifecycle_status: str | None = Query(default=None),
    infrastructure_type: str | None = Query(default=None),
    cloud_provider: str | None = Query(default=None),
    limit: int = Query(default=DEFAULT_LIST_LIMIT, ge=1, le=MAX_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
    _tenant: TenantContext = Depends(require_permission(Permission.INFRASTRUCTURE_READ)),
) -> PaginatedInfrastructureListResponse:
    items = await svc.list(
        ListInfrastructureQuery(
            tenant_id=tenant_id,
            lifecycle_status=lifecycle_status,
            infrastructure_type=infrastructure_type,
            cloud_provider=cloud_provider,
            limit=limit,
            offset=offset,
        )
    )
    summaries = [_summary_response(i) for i in items]
    return PaginatedInfrastructureListResponse(
        items=summaries, count=len(summaries), limit=limit, offset=offset
    )


@infrastructure_router.get(
    "/global",
    response_model=PaginatedInfrastructureListResponse,
    summary="List global adversary Infrastructure records",
)
async def list_global_infrastructure(
    svc: InfrastructureServiceDep,
    lifecycle_status: str | None = Query(default=None),
    infrastructure_type: str | None = Query(default=None),
    cloud_provider: str | None = Query(default=None),
    limit: int = Query(default=DEFAULT_LIST_LIMIT, ge=1, le=MAX_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
    _platform: PlatformContext = Depends(
        require_platform_permission(PlatformPermission.PLATFORM_INFRASTRUCTURE_READ)
    ),
) -> PaginatedInfrastructureListResponse:
    items = await svc.list(
        ListInfrastructureQuery(
            tenant_id=None,
            lifecycle_status=lifecycle_status,
            infrastructure_type=infrastructure_type,
            cloud_provider=cloud_provider,
            limit=limit,
            offset=offset,
        )
    )
    summaries = [_summary_response(i) for i in items]
    return PaginatedInfrastructureListResponse(
        items=summaries, count=len(summaries), limit=limit, offset=offset
    )


# ── Canonical single routes per {infrastructure_id} operation ──────────


@infrastructure_router.get(
    "/{infrastructure_id}",
    response_model=InfrastructureDetailResponse,
    summary="Get an adversary Infrastructure record",
)
async def get_infrastructure(
    infrastructure_id: str,
    svc: InfrastructureServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> InfrastructureDetailResponse:
    tenant_id = await _authorize_scope(
        infrastructure_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.INFRASTRUCTURE_READ,
        platform_permission=PlatformPermission.PLATFORM_INFRASTRUCTURE_READ,
    )
    dto = await svc.get(
        GetInfrastructureQuery(tenant_id=tenant_id, infrastructure_id=infrastructure_id)
    )
    return _detail_response(dto)


@infrastructure_router.post(
    "/{infrastructure_id}/hosting-provider",
    response_model=InfrastructureDetailResponse,
    summary="Set the hosting provider",
)
async def set_hosting_provider(
    infrastructure_id: str,
    body: SetHostingProviderRequest,
    svc: InfrastructureServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> InfrastructureDetailResponse:
    tenant_id = await _authorize_scope(
        infrastructure_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.INFRASTRUCTURE_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_INFRASTRUCTURE_MANAGE,
    )
    dto = await svc.set_hosting_provider(
        SetHostingProviderCommand(
            tenant_id=tenant_id,
            infrastructure_id=infrastructure_id,
            provider_name=body.provider_name,
        )
    )
    return _detail_response(dto)


@infrastructure_router.post(
    "/{infrastructure_id}/cloud-provider",
    response_model=InfrastructureDetailResponse,
    summary="Set the cloud tenancy",
)
async def set_cloud_provider(
    infrastructure_id: str,
    body: SetCloudProviderRequest,
    svc: InfrastructureServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> InfrastructureDetailResponse:
    tenant_id = await _authorize_scope(
        infrastructure_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.INFRASTRUCTURE_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_INFRASTRUCTURE_MANAGE,
    )
    dto = await svc.set_cloud_provider(
        SetCloudProviderCommand(
            tenant_id=tenant_id,
            infrastructure_id=infrastructure_id,
            provider=body.provider,
        )
    )
    return _detail_response(dto)


@infrastructure_router.post(
    "/{infrastructure_id}/regions",
    response_model=InfrastructureDetailResponse,
    summary="Add an operating region",
)
async def add_region(
    infrastructure_id: str,
    body: AddRegionRequest,
    svc: InfrastructureServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> InfrastructureDetailResponse:
    tenant_id = await _authorize_scope(
        infrastructure_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.INFRASTRUCTURE_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_INFRASTRUCTURE_MANAGE,
    )
    dto = await svc.add_region(
        AddRegionCommand(
            tenant_id=tenant_id,
            infrastructure_id=infrastructure_id,
            region_code=body.region_code,
        )
    )
    return _detail_response(dto)


@infrastructure_router.post(
    "/{infrastructure_id}/network-ownership",
    response_model=InfrastructureDetailResponse,
    summary="Set registrant / abuse-contact network ownership",
)
async def set_network_ownership(
    infrastructure_id: str,
    body: SetNetworkOwnershipRequest,
    svc: InfrastructureServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> InfrastructureDetailResponse:
    tenant_id = await _authorize_scope(
        infrastructure_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.INFRASTRUCTURE_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_INFRASTRUCTURE_MANAGE,
    )
    dto = await svc.set_network_ownership(
        SetNetworkOwnershipCommand(
            tenant_id=tenant_id,
            infrastructure_id=infrastructure_id,
            ownership=_to_ownership_input(body.ownership),
        )
    )
    return _detail_response(dto)


@infrastructure_router.post(
    "/{infrastructure_id}/evidence-citations",
    response_model=InfrastructureDetailResponse,
    summary="Add an evidence citation",
)
async def add_evidence_citation(
    infrastructure_id: str,
    body: AddEvidenceCitationRequest,
    svc: InfrastructureServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> InfrastructureDetailResponse:
    tenant_id = await _authorize_scope(
        infrastructure_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.INFRASTRUCTURE_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_INFRASTRUCTURE_MANAGE,
    )
    dto = await svc.add_evidence_citation(
        AddEvidenceCitationCommand(
            tenant_id=tenant_id,
            infrastructure_id=infrastructure_id,
            citation=body.citation,
        )
    )
    return _detail_response(dto)


@infrastructure_router.post(
    "/{infrastructure_id}/source-attributions",
    response_model=InfrastructureDetailResponse,
    summary="Add a source attribution",
)
async def add_source_attribution(
    infrastructure_id: str,
    body: AddSourceAttributionRequest,
    svc: InfrastructureServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> InfrastructureDetailResponse:
    tenant_id = await _authorize_scope(
        infrastructure_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.INFRASTRUCTURE_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_INFRASTRUCTURE_MANAGE,
    )
    dto = await svc.add_source_attribution(
        AddSourceAttributionCommand(
            tenant_id=tenant_id,
            infrastructure_id=infrastructure_id,
            attribution=_to_attribution_input(body.attribution),
        )
    )
    return _detail_response(dto)


@infrastructure_router.patch(
    "/{infrastructure_id}/deprecate",
    response_model=InfrastructureDetailResponse,
    summary="Deprecate an Infrastructure RECORD",
)
async def deprecate_infrastructure(
    infrastructure_id: str,
    body: LifecycleTransitionRequest,
    svc: InfrastructureServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> InfrastructureDetailResponse:
    tenant_id = await _authorize_scope(
        infrastructure_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.INFRASTRUCTURE_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_INFRASTRUCTURE_MANAGE,
    )
    dto = await svc.deprecate(
        DeprecateInfrastructureCommand(
            tenant_id=tenant_id,
            infrastructure_id=infrastructure_id,
            evidence=_to_attribution_input(body.evidence),
        )
    )
    return _detail_response(dto)


@infrastructure_router.patch(
    "/{infrastructure_id}/revoke",
    response_model=InfrastructureDetailResponse,
    summary="Revoke an Infrastructure RECORD",
)
async def revoke_infrastructure(
    infrastructure_id: str,
    body: LifecycleTransitionRequest,
    svc: InfrastructureServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> InfrastructureDetailResponse:
    tenant_id = await _authorize_scope(
        infrastructure_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.INFRASTRUCTURE_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_INFRASTRUCTURE_MANAGE,
    )
    dto = await svc.revoke(
        RevokeInfrastructureCommand(
            tenant_id=tenant_id,
            infrastructure_id=infrastructure_id,
            evidence=_to_attribution_input(body.evidence),
        )
    )
    return _detail_response(dto)


@infrastructure_router.patch(
    "/{infrastructure_id}/supersede",
    response_model=InfrastructureDetailResponse,
    summary="Supersede an Infrastructure RECORD",
)
async def supersede_infrastructure(
    infrastructure_id: str,
    body: SupersedeInfrastructureRequest,
    svc: InfrastructureServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> InfrastructureDetailResponse:
    tenant_id = await _authorize_scope(
        infrastructure_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.INFRASTRUCTURE_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_INFRASTRUCTURE_MANAGE,
    )
    dto = await svc.supersede(
        SupersedeInfrastructureCommand(
            tenant_id=tenant_id,
            infrastructure_id=infrastructure_id,
            superseded_by=body.superseded_by,
            evidence=_to_attribution_input(body.evidence),
        )
    )
    return _detail_response(dto)


@infrastructure_router.patch(
    "/{infrastructure_id}/reactivate",
    response_model=InfrastructureDetailResponse,
    summary="Reactivate an Infrastructure RECORD",
)
async def reactivate_infrastructure(
    infrastructure_id: str,
    body: LifecycleTransitionRequest,
    svc: InfrastructureServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> InfrastructureDetailResponse:
    tenant_id = await _authorize_scope(
        infrastructure_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.INFRASTRUCTURE_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_INFRASTRUCTURE_MANAGE,
    )
    dto = await svc.reactivate(
        ReactivateInfrastructureCommand(
            tenant_id=tenant_id,
            infrastructure_id=infrastructure_id,
            evidence=_to_attribution_input(body.evidence),
        )
    )
    return _detail_response(dto)
