"""Adversary-Tool Intelligence API router, mirroring
`campaign_intel.api.v1.campaigns`'s exact ownership-based authorization
shape: `POST /observations/tenant` and `POST /observations/global`
remain two explicit routes (ownership must be stated up front — no
existing Tool to load yet); `GET /` (tenant list) and `GET /global`
(global list) are unambiguous, non-duplicated paths; every `{tool_id}`
operation is ONE canonical route, authorizing dynamically from the
*loaded Tool's own ownership scope* (`Tool.tenant_id`, resolved via
`ToolApplicationService.get_scope`) rather than from which URL prefix
the caller happened to use:

    scope = await svc.get_scope(tool_id)   # TenantId | None; 404 if missing
    if scope is None:                      # global
        require platform.has_permission(...)   # else 403
    else:                                  # tenant-owned
        require tenant is not None and tenant.organization_id == str(scope)
                                                 # else 404 (cross-tenant)
        require tenant.has_permission(...)      # else 403

The URL prefix is `/tool-intel` — deliberately distinct from anything
AI-agent function/tool-calling might claim, since those are unrelated
concepts that merely share the English word "tool".

`deprecate`/`revoke`/`supersede`/`reactivate` move RedForge's own RECORD
lifecycle — never a claim about the real-world tool's continued use.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, Query, Response, status

from redforge.api.security import (
    TenantContext,
    require_permission,
    require_platform_permission,
)
from redforge.domain.identity.value_objects import Permission
from redforge.domain.platform_identity.value_objects import PlatformPermission
from tool_intel.api.dependencies import (
    OptionalTenantContextDep,
    PlatformContextDep,
    TenantIdDep,
    ToolServiceDep,
)
from tool_intel.api.schemas.tool_schemas import (
    AddAliasRequest,
    AddCapabilityRequest,
    AddEvidenceCitationRequest,
    AddPlatformRequest,
    AddSourceAttributionRequest,
    LifecycleTransitionRequest,
    ObserveToolRequest,
    PaginatedToolListResponse,
    SourceAttributionRequest,
    SourceAttributionResponse,
    SupersedeToolRequest,
    ToolDetailResponse,
    ToolSummaryResponse,
    VersionRecordResponse,
)
from tool_intel.application.commands.tool_commands import (
    AddAliasCommand,
    AddCapabilityCommand,
    AddEvidenceCitationCommand,
    AddPlatformCommand,
    AddSourceAttributionCommand,
    DeprecateToolCommand,
    ObserveToolCommand,
    ReactivateToolCommand,
    RevokeToolCommand,
    SourceAttributionInput,
    SupersedeToolCommand,
)
from tool_intel.application.exceptions import (
    ApplicationForbiddenError,
    ApplicationNotFoundError,
)
from tool_intel.application.queries.tool_queries import (
    DEFAULT_LIST_LIMIT,
    MAX_LIST_LIMIT,
    GetToolQuery,
    ListToolsQuery,
)

if TYPE_CHECKING:
    from redforge.api.security import PlatformContext
    from tool_intel.application.dtos.tool_dtos import ToolDetailDTO, ToolSummaryDTO
    from tool_intel.application.services.tool_application_service import (
        ToolApplicationService,
    )
    from tool_intel.domain.value_objects.identifiers import TenantId

tool_router = APIRouter()


async def _authorize_scope(
    tool_id: str,
    svc: ToolApplicationService,
    tenant: TenantContext | None,
    platform: PlatformContext,
    *,
    tenant_permission: Permission,
    platform_permission: PlatformPermission,
) -> TenantId | None:
    """The single ownership-based authorization decision every canonical
    `{tool_id}` route uses. Raises `ApplicationNotFoundError` (404) if
    the Tool doesn't exist, `ApplicationForbiddenError` (403) if the
    caller lacks the required authority for the resource's actual scope,
    or returns the `tenant_id` to use for the real, authorized operation
    (`None` for global)."""
    scope = await svc.get_scope(tool_id)
    if scope is None:
        if not platform.has_permission(platform_permission):
            raise ApplicationForbiddenError(platform_permission.value)
        return None
    if tenant is None or tenant.organization_id != str(scope):
        raise ApplicationNotFoundError("Tool", tool_id)
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


def _detail_response(dto: ToolDetailDTO) -> ToolDetailResponse:
    return ToolDetailResponse(
        tool_id=dto.tool_id,
        tenant_id=dto.tenant_id,
        canonical_name=dto.canonical_name,
        category=dto.category,
        lifecycle_status=dto.lifecycle_status,
        family=dto.family,
        confidence=dto.confidence,
        superseded_by=dto.superseded_by,
        created_at=dto.created_at,
        updated_at=dto.updated_at,
        aliases=list(dto.aliases),
        platforms=list(dto.platforms),
        capabilities=list(dto.capabilities),
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


def _summary_response(dto: ToolSummaryDTO) -> ToolSummaryResponse:
    return ToolSummaryResponse(
        tool_id=dto.tool_id,
        tenant_id=dto.tenant_id,
        canonical_name=dto.canonical_name,
        category=dto.category,
        lifecycle_status=dto.lifecycle_status,
        family=dto.family,
        confidence=dto.confidence,
        created_at=dto.created_at,
        updated_at=dto.updated_at,
        alias_count=dto.alias_count,
        platform_count=dto.platform_count,
        capability_count=dto.capability_count,
    )


def _observe_command(body: ObserveToolRequest, tenant_id: TenantId | None) -> ObserveToolCommand:
    return ObserveToolCommand(
        tenant_id=tenant_id,
        canonical_name=body.canonical_name,
        category=body.category,
        family=body.family,
        confidence=body.confidence,
        aliases=tuple(body.aliases),
        platforms=tuple(body.platforms),
        capabilities=tuple(body.capabilities),
    )


# ── Observation (ownership stated explicitly — no existing Tool) ────────


@tool_router.post(
    "/observations/tenant",
    status_code=status.HTTP_201_CREATED,
    response_model=ToolDetailResponse,
    summary="Observe a tenant-scoped adversary Tool",
    description=(
        "Tenant-scoped adversary-tool observation. `canonical_name` is "
        "strongly normalized and deduplicated within this tenant's "
        "scope — never creates a second identity for the same normalized "
        "name."
    ),
)
async def observe_tenant_tool(
    body: ObserveToolRequest,
    response: Response,
    tenant_id: TenantIdDep,
    svc: ToolServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.TOOL_OBSERVE)),
) -> ToolDetailResponse:
    dto = await svc.observe(_observe_command(body, tenant_id))
    response.headers["Location"] = f"/api/v1/tool-intel/{dto.tool_id}"
    return _detail_response(dto)


@tool_router.post(
    "/observations/global",
    status_code=status.HTTP_201_CREATED,
    response_model=ToolDetailResponse,
    summary="Observe a global adversary Tool (platform authority required)",
    description=(
        "Global, RedForge-curated adversary Tool. Requires platform "
        "authority (PLATFORM_TOOL_MANAGE) — no organization OWNER/ADMIN/"
        "SECURITY_MANAGER membership satisfies this."
    ),
)
async def observe_global_tool(
    body: ObserveToolRequest,
    response: Response,
    svc: ToolServiceDep,
    _platform: PlatformContext = Depends(
        require_platform_permission(PlatformPermission.PLATFORM_TOOL_MANAGE)
    ),
) -> ToolDetailResponse:
    dto = await svc.observe(_observe_command(body, None))
    response.headers["Location"] = f"/api/v1/tool-intel/{dto.tool_id}"
    return _detail_response(dto)


# ── Lists (unambiguous, distinct paths) ─────────────────────────────────


@tool_router.get(
    "",
    response_model=PaginatedToolListResponse,
    summary="List this tenant's adversary Tool records",
)
async def list_tenant_tools(
    tenant_id: TenantIdDep,
    svc: ToolServiceDep,
    lifecycle_status: str | None = Query(default=None),
    category: str | None = Query(default=None),
    platform: str | None = Query(default=None),
    capability: str | None = Query(default=None),
    limit: int = Query(default=DEFAULT_LIST_LIMIT, ge=1, le=MAX_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
    _tenant: TenantContext = Depends(require_permission(Permission.TOOL_READ)),
) -> PaginatedToolListResponse:
    items = await svc.list(
        ListToolsQuery(
            tenant_id=tenant_id,
            lifecycle_status=lifecycle_status,
            category=category,
            platform=platform,
            capability=capability,
            limit=limit,
            offset=offset,
        )
    )
    summaries = [_summary_response(i) for i in items]
    return PaginatedToolListResponse(
        items=summaries, count=len(summaries), limit=limit, offset=offset
    )


@tool_router.get(
    "/global",
    response_model=PaginatedToolListResponse,
    summary="List global adversary Tool records",
)
async def list_global_tools(
    svc: ToolServiceDep,
    lifecycle_status: str | None = Query(default=None),
    category: str | None = Query(default=None),
    platform: str | None = Query(default=None),
    capability: str | None = Query(default=None),
    limit: int = Query(default=DEFAULT_LIST_LIMIT, ge=1, le=MAX_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
    _platform: PlatformContext = Depends(
        require_platform_permission(PlatformPermission.PLATFORM_TOOL_READ)
    ),
) -> PaginatedToolListResponse:
    items = await svc.list(
        ListToolsQuery(
            tenant_id=None,
            lifecycle_status=lifecycle_status,
            category=category,
            platform=platform,
            capability=capability,
            limit=limit,
            offset=offset,
        )
    )
    summaries = [_summary_response(i) for i in items]
    return PaginatedToolListResponse(
        items=summaries, count=len(summaries), limit=limit, offset=offset
    )


# ── Canonical single routes per {tool_id} operation ────────────────────


@tool_router.get(
    "/{tool_id}",
    response_model=ToolDetailResponse,
    summary="Get an adversary Tool record",
)
async def get_tool(
    tool_id: str,
    svc: ToolServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> ToolDetailResponse:
    tenant_id = await _authorize_scope(
        tool_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.TOOL_READ,
        platform_permission=PlatformPermission.PLATFORM_TOOL_READ,
    )
    dto = await svc.get(GetToolQuery(tenant_id=tenant_id, tool_id=tool_id))
    return _detail_response(dto)


@tool_router.post(
    "/{tool_id}/aliases",
    response_model=ToolDetailResponse,
    summary="Add an alias",
)
async def add_alias(
    tool_id: str,
    body: AddAliasRequest,
    svc: ToolServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> ToolDetailResponse:
    tenant_id = await _authorize_scope(
        tool_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.TOOL_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_TOOL_MANAGE,
    )
    dto = await svc.add_alias(
        AddAliasCommand(tenant_id=tenant_id, tool_id=tool_id, alias=body.alias)
    )
    return _detail_response(dto)


@tool_router.post(
    "/{tool_id}/platforms",
    response_model=ToolDetailResponse,
    summary="Add a supported platform",
)
async def add_platform(
    tool_id: str,
    body: AddPlatformRequest,
    svc: ToolServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> ToolDetailResponse:
    tenant_id = await _authorize_scope(
        tool_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.TOOL_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_TOOL_MANAGE,
    )
    dto = await svc.add_platform(
        AddPlatformCommand(tenant_id=tenant_id, tool_id=tool_id, platform=body.platform)
    )
    return _detail_response(dto)


@tool_router.post(
    "/{tool_id}/capabilities",
    response_model=ToolDetailResponse,
    summary="Add an operational capability",
)
async def add_capability(
    tool_id: str,
    body: AddCapabilityRequest,
    svc: ToolServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> ToolDetailResponse:
    tenant_id = await _authorize_scope(
        tool_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.TOOL_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_TOOL_MANAGE,
    )
    dto = await svc.add_capability(
        AddCapabilityCommand(tenant_id=tenant_id, tool_id=tool_id, capability=body.capability)
    )
    return _detail_response(dto)


@tool_router.post(
    "/{tool_id}/evidence-citations",
    response_model=ToolDetailResponse,
    summary="Add an evidence citation",
)
async def add_evidence_citation(
    tool_id: str,
    body: AddEvidenceCitationRequest,
    svc: ToolServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> ToolDetailResponse:
    tenant_id = await _authorize_scope(
        tool_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.TOOL_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_TOOL_MANAGE,
    )
    dto = await svc.add_evidence_citation(
        AddEvidenceCitationCommand(tenant_id=tenant_id, tool_id=tool_id, citation=body.citation)
    )
    return _detail_response(dto)


@tool_router.post(
    "/{tool_id}/source-attributions",
    response_model=ToolDetailResponse,
    summary="Add a source attribution",
)
async def add_source_attribution(
    tool_id: str,
    body: AddSourceAttributionRequest,
    svc: ToolServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> ToolDetailResponse:
    tenant_id = await _authorize_scope(
        tool_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.TOOL_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_TOOL_MANAGE,
    )
    dto = await svc.add_source_attribution(
        AddSourceAttributionCommand(
            tenant_id=tenant_id,
            tool_id=tool_id,
            attribution=_to_attribution_input(body.attribution),
        )
    )
    return _detail_response(dto)


@tool_router.patch(
    "/{tool_id}/deprecate",
    response_model=ToolDetailResponse,
    summary="Deprecate a Tool RECORD",
)
async def deprecate_tool(
    tool_id: str,
    body: LifecycleTransitionRequest,
    svc: ToolServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> ToolDetailResponse:
    tenant_id = await _authorize_scope(
        tool_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.TOOL_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_TOOL_MANAGE,
    )
    dto = await svc.deprecate(
        DeprecateToolCommand(
            tenant_id=tenant_id,
            tool_id=tool_id,
            evidence=_to_attribution_input(body.evidence),
        )
    )
    return _detail_response(dto)


@tool_router.patch(
    "/{tool_id}/revoke",
    response_model=ToolDetailResponse,
    summary="Revoke a Tool RECORD",
)
async def revoke_tool(
    tool_id: str,
    body: LifecycleTransitionRequest,
    svc: ToolServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> ToolDetailResponse:
    tenant_id = await _authorize_scope(
        tool_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.TOOL_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_TOOL_MANAGE,
    )
    dto = await svc.revoke(
        RevokeToolCommand(
            tenant_id=tenant_id,
            tool_id=tool_id,
            evidence=_to_attribution_input(body.evidence),
        )
    )
    return _detail_response(dto)


@tool_router.patch(
    "/{tool_id}/supersede",
    response_model=ToolDetailResponse,
    summary="Supersede a Tool RECORD",
)
async def supersede_tool(
    tool_id: str,
    body: SupersedeToolRequest,
    svc: ToolServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> ToolDetailResponse:
    tenant_id = await _authorize_scope(
        tool_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.TOOL_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_TOOL_MANAGE,
    )
    dto = await svc.supersede(
        SupersedeToolCommand(
            tenant_id=tenant_id,
            tool_id=tool_id,
            superseded_by=body.superseded_by,
            evidence=_to_attribution_input(body.evidence),
        )
    )
    return _detail_response(dto)


@tool_router.patch(
    "/{tool_id}/reactivate",
    response_model=ToolDetailResponse,
    summary="Reactivate a Tool RECORD",
)
async def reactivate_tool(
    tool_id: str,
    body: LifecycleTransitionRequest,
    svc: ToolServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> ToolDetailResponse:
    tenant_id = await _authorize_scope(
        tool_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.TOOL_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_TOOL_MANAGE,
    )
    dto = await svc.reactivate(
        ReactivateToolCommand(
            tenant_id=tenant_id,
            tool_id=tool_id,
            evidence=_to_attribution_input(body.evidence),
        )
    )
    return _detail_response(dto)
