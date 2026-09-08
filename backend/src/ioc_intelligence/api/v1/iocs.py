"""IOC Intelligence API router (M51.2 Phase A4, corrected Phase A4.1).

Endpoint set is bounded strictly by what `IOCApplicationService` already
exposes (Phase A2, certified) — no endpoint here invents a capability
the application layer does not already have. Every handler does
exactly one thing: authorize, build a command/query with `tenant_id`
from a trusted source (never the request body), call the service, map
the DTO to a response model. No repository/session access, no
business logic, no domain object crosses this boundary.

Phase A4.1 correction: the earlier Phase A4 design created a static
`/global/...` sibling route for every `{ioc_id}` operation (24 routes
total) to keep authorization purely static per-route. Repository-first
review of comparable "resource may be tenant-owned or platform-global"
precedent elsewhere in the platform found no existing bounded context
that duplicates its entire mutation surface this way — the closest
analogue, `threat_actor_intel`, has exactly ONE canonical route per
`{threat_actor_id}` operation, because `ThreatActor` itself is *always*
global (ADR-M51.1-02); it never had this ambiguity to begin with. IOC
is the first aggregate in this codebase that is genuinely
dual-scoped, so there is no "keep the duplication, it's the existing
pattern" precedent to defer to — the duplication was purely this
router's own earlier design choice, not a codebase convention.

This version keeps exactly ONE canonical route per `{ioc_id}`
operation (GET, sources, evidence, lifecycle, epistemic-state,
dispute, refute, refresh, supersede, revoke — 10 routes), authorizing
each dynamically from the *loaded IOC's own ownership scope*
(`IOC.tenant_id`, resolved via `IOCApplicationService.get_ioc_scope`)
rather than from which URL prefix the caller happened to use:

    scope = await svc.get_ioc_scope(ioc_id)   # TenantId | None; 404 if missing
    if scope is None:                          # global
        require platform.has_permission(...)   # else 403
    else:                                       # tenant-owned
        require tenant is not None and tenant.organization_id == str(scope)
                                                 # else 404 (cross-tenant, unchanged
                                                 #           not-found semantics —
                                                 #           platform authority is
                                                 #           NEVER consulted here)
        require tenant.has_permission(...)      # else 403

This is composed entirely from the existing `TenantContext.
has_permission`/`PlatformContext.has_permission` primitives — no new
role, permission, or credential concept is introduced; it is an
authorization *decision tree*, not a new framework.

`POST /observations/tenant` and `POST /observations/global` remain two
explicit routes (per the mission's own preferred design) because
*creation* ownership must be stated up front — there is no existing
IOC to load and inspect yet, so the ownership-scope-from-load pattern
above does not apply. `GET /iocs` (tenant list) and `GET /iocs/global`
(global list) are also retained unchanged: they were never part of the
{ioc_id}-operation duplication this phase corrects — each already had
its own single, unambiguous, non-duplicated path.

Global mutation step-up assurance (Phase A4.1 Objective 2): NOT added.
See the Phase A4.1 final report for the full evidence survey — every
comparable global reference/catalog-mutation permission tier in this
codebase (`PLATFORM_THREAT_INTEL_MANAGE`, `PLATFORM_FEED_SYNC_MANAGE`,
`PLATFORM_THREAT_FUSION_MANAGE`, `PLATFORM_COMPLIANCE_CATALOG_MANAGE`)
uses plain `require_platform_permission`, never
`require_platform_permission_with_assurance`. That mechanism is used
by exactly six endpoints platform-wide (`src/redforge/api/v1/
platform.py`), all in the identity/access-lifecycle class (suspend/
reactivate a user or organization; grant/revoke platform access
itself) — a categorically different, materially riskier class of
action than curating IOC reference data. This is the frozen repository
policy the mission's own Objective 2 escape clause anticipates."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog
from fastapi import APIRouter, Depends, Query, Response, status

from ioc_intelligence.api.dependencies import (
    IocServiceDep,
    OptionalTenantContextDep,
    PlatformContextDep,
    TenantIdDep,
)
from ioc_intelligence.api.schemas.ioc_schemas import (
    AddEvidenceCitationRequest,
    AddSourceAttributionRequest,
    EvidenceCitationResponse,
    ExpireLapsedIocsResponse,
    IocDetailResponse,
    IocSummaryResponse,
    ObserveIocRequest,
    PaginatedIocListResponse,
    RefuteIocRequest,
    SourceAttributionResponse,
    TransitionEpistemicStateRequest,
    TransitionLifecycleRequest,
)
from ioc_intelligence.application._auth import IocIntelRole
from ioc_intelligence.application.commands.ioc_commands import (
    AddEvidenceCitationCommand,
    AddSourceAttributionCommand,
    MarkDisputedCommand,
    ObserveGlobalIocCommand,
    ObserveTenantIocCommand,
    RefreshValidityCommand,
    RefuteIocCommand,
    RevokeIocCommand,
    SourceAttributionInput,
    SupersedeIocCommand,
    TransitionEpistemicStateCommand,
    TransitionLifecycleCommand,
)
from ioc_intelligence.application.exceptions import (
    ApplicationForbiddenError,
    ApplicationNotFoundError,
)
from ioc_intelligence.application.queries.ioc_queries import (
    DEFAULT_LIST_LIMIT,
    MAX_LIST_LIMIT,
    MAX_SEARCH_LENGTH,
    GetIocQuery,
    IocSortField,
    ListIocsQuery,
    SortDirection,
)
from redforge.api.security import (
    TenantContext,
    require_permission,
    require_platform_permission,
)
from redforge.domain.identity.value_objects import Permission
from redforge.domain.platform_identity.value_objects import PlatformPermission

if TYPE_CHECKING:
    from ioc_intelligence.application.dtos.ioc_dtos import IocDetailDTO, IocSummaryDTO
    from ioc_intelligence.application.services.ioc_application_service import (
        IOCApplicationService,
    )
    from ioc_intelligence.domain.value_objects.identifiers import TenantId
    from redforge.api.security import PlatformContext

iocs_router = APIRouter()

_TENANT_ROLES = (IocIntelRole.ANALYST.value,)
_TENANT_VIEWER_ROLES = (IocIntelRole.VIEWER.value,)
_PLATFORM_ROLES = (IocIntelRole.PLATFORM_ADMIN.value,)

_logger = structlog.get_logger(__name__)


def _log_mutation(event: str, *, ioc_id: str, tenant_id: str | None, **extra: object) -> None:
    """Structured business-event log for a security-relevant IOC
    mutation. Deliberately logs only identifiers/type/outcome fields —
    never evidence citation content, source attribution payloads, or
    any other IOC-sensitive material. A request-tracing id is already
    bound to every log call automatically by the platform's existing
    request-tracing middleware (structlog contextvars) — this
    function adds no second observability mechanism, it only emits
    IOC-specific business events through the same structlog pipeline
    every other bounded context already uses."""
    _logger.info(event, ioc_id=ioc_id, tenant_id=tenant_id or "global", **extra)


async def _authorize_ioc_scope(
    ioc_id: str,
    svc: IOCApplicationService,
    tenant: TenantContext | None,
    platform: PlatformContext,
    *,
    tenant_permission: Permission,
    platform_permission: PlatformPermission,
) -> TenantId | None:
    """The single ownership-based authorization decision every
    canonical `{ioc_id}` route uses. Raises `ApplicationNotFoundError`
    (404) if the IOC doesn't exist, `ApplicationForbiddenError` (403)
    if the caller lacks the required authority for the resource's
    actual scope, or returns the `tenant_id` to use for the real,
    authorized operation (`None` for global)."""
    scope = await svc.get_ioc_scope(ioc_id)
    if scope is None:
        if not platform.has_permission(platform_permission):
            raise ApplicationForbiddenError(platform_permission.value)
        return None
    # Tenant-owned: platform authority is never consulted here — a
    # platform-authorized caller with no matching TenantContext (or a
    # TenantContext scoped to a *different* organization) gets the
    # exact same not-found response as any other cross-tenant caller.
    if tenant is None or tenant.organization_id != str(scope):
        raise ApplicationNotFoundError("IOC", ioc_id)
    if not tenant.has_permission(tenant_permission):
        raise ApplicationForbiddenError(tenant_permission.value)
    return scope


def _to_attribution_input(body: AddSourceAttributionRequest) -> SourceAttributionInput:
    return SourceAttributionInput(
        source_system=body.attribution.source_system,
        external_id=body.attribution.external_id,
        observed_at=body.attribution.observed_at,
        weight_applied=body.attribution.weight_applied,
        confidence=body.attribution.confidence,
        content_hash=body.attribution.content_hash,
    )


def _detail_response(dto: IocDetailDTO) -> IocDetailResponse:
    return IocDetailResponse(
        ioc_id=dto.ioc_id,
        tenant_id=dto.tenant_id,
        ioc_type=dto.ioc_type,
        canonical_key=dto.canonical_key,
        lifecycle=dto.lifecycle.value,
        epistemic_state=dto.epistemic_state.value,
        valid_from=dto.valid_from,
        valid_until=dto.valid_until,
        created_at=dto.created_at,
        updated_at=dto.updated_at,
        source_attributions=[
            SourceAttributionResponse(
                source_system=a.source_system,
                external_id=a.external_id,
                content_hash=a.content_hash,
                observed_at=a.observed_at,
                weight_applied=a.weight_applied,
                confidence=a.confidence,
            )
            for a in dto.source_attributions
        ],
        evidence_citations=[
            EvidenceCitationResponse(value=c.value) for c in dto.evidence_citations
        ],
    )


def _summary_response(dto: IocSummaryDTO) -> IocSummaryResponse:
    return IocSummaryResponse(
        ioc_id=dto.ioc_id,
        tenant_id=dto.tenant_id,
        ioc_type=dto.ioc_type,
        canonical_key=dto.canonical_key,
        lifecycle=dto.lifecycle.value,
        epistemic_state=dto.epistemic_state.value,
        created_at=dto.created_at,
        updated_at=dto.updated_at,
        valid_until=dto.valid_until,
        source_count=dto.source_count,
        evidence_count=dto.evidence_count,
    )


def _actor_roles(tenant_id: TenantId | None) -> tuple[str, ...]:
    return _PLATFORM_ROLES if tenant_id is None else _TENANT_ROLES


# ── Observation (ownership must be stated explicitly — no existing IOC to load) ──


@iocs_router.post(
    "/observations/tenant",
    status_code=status.HTTP_201_CREATED,
    response_model=IocDetailResponse,
    summary="Observe a tenant-scoped IOC",
    description=(
        "Tenant-scoped IOC observation backed by that tenant's own evidence "
        "or an approved source attribution. Deduplicates against any "
        "existing IOC for this tenant with the same canonical value — "
        "never creates a second identity."
    ),
)
async def observe_tenant_ioc(
    body: ObserveIocRequest,
    response: Response,
    tenant_id: TenantIdDep,
    svc: IocServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.IOC_INTEL_OBSERVE)),
) -> IocDetailResponse:
    dto = await svc.observe_tenant_ioc(
        ObserveTenantIocCommand(
            tenant_id=tenant_id,
            ioc_type=body.ioc_type,
            raw_value=body.raw_value,
            source_attributions=tuple(
                SourceAttributionInput(
                    source_system=a.source_system,
                    external_id=a.external_id,
                    observed_at=a.observed_at,
                    weight_applied=a.weight_applied,
                    confidence=a.confidence,
                    content_hash=a.content_hash,
                )
                for a in body.source_attributions
            ),
            evidence_citations=tuple(c.to_canonical_citation() for c in body.evidence_citations),
            actor_roles=_TENANT_ROLES,
        )
    )
    _log_mutation("ioc_observed", ioc_id=dto.ioc_id, tenant_id=dto.tenant_id, scope="tenant")
    response.headers["Location"] = f"/api/v1/iocs/{dto.ioc_id}"
    return _detail_response(dto)


@iocs_router.post(
    "/observations/global",
    status_code=status.HTTP_201_CREATED,
    response_model=IocDetailResponse,
    summary="Observe a global IOC (platform authority required)",
    description=(
        "Global IOC intelligence from an approved shared source. Requires "
        "platform authority (PLATFORM_IOC_INTEL_MANAGE) — no organization "
        "OWNER/ADMIN/SECURITY_MANAGER membership satisfies this. Sensitive "
        "global mutation; see module docstring for the step-up-assurance "
        "evidence survey (none required, matching frozen precedent)."
    ),
)
async def observe_global_ioc(
    body: ObserveIocRequest,
    response: Response,
    svc: IocServiceDep,
    _platform: PlatformContext = Depends(
        require_platform_permission(PlatformPermission.PLATFORM_IOC_INTEL_MANAGE)
    ),
) -> IocDetailResponse:
    dto = await svc.observe_global_ioc(
        ObserveGlobalIocCommand(
            ioc_type=body.ioc_type,
            raw_value=body.raw_value,
            source_attributions=tuple(
                SourceAttributionInput(
                    source_system=a.source_system,
                    external_id=a.external_id,
                    observed_at=a.observed_at,
                    weight_applied=a.weight_applied,
                    confidence=a.confidence,
                    content_hash=a.content_hash,
                )
                for a in body.source_attributions
            ),
            evidence_citations=tuple(c.to_canonical_citation() for c in body.evidence_citations),
            actor_roles=_PLATFORM_ROLES,
        )
    )
    _log_mutation("ioc_observed", ioc_id=dto.ioc_id, tenant_id=dto.tenant_id, scope="global")
    response.headers["Location"] = f"/api/v1/iocs/{dto.ioc_id}"
    return _detail_response(dto)


@iocs_router.post(
    "/maintenance/expire-lapsed",
    response_model=ExpireLapsedIocsResponse,
    summary="Expire IOCs whose validity window has lapsed (platform authority required)",
    description=(
        "Bounded maintenance sweep: transitions every ACTIVE IOC (tenant "
        "and global) whose valid_until has already passed to EXPIRED. "
        "Platform-only — crosses every tenant. As of M51.2 Slice 2.1 this "
        "sweep also runs automatically on an in-process periodic schedule "
        "(`ioc_expiry_scheduler`, see redforge.app) — this endpoint remains "
        "available for a manual operator trigger or an external cron/k8s "
        "CronJob, and calls the exact same idempotent application-service "
        "method the scheduler does. Idempotent and safe under concurrent "
        "invocation (manual + scheduled, or multiple app instances): "
        "repeat/overlapping calls only ever act on IOCs still ACTIVE past "
        "their validity window, and per-row optimistic-concurrency "
        "handling means an overlapping sweep skips (never double-applies "
        "or corrupts) a row another sweep already expired."
    ),
)
async def expire_lapsed_iocs(
    svc: IocServiceDep,
    _platform: PlatformContext = Depends(
        require_platform_permission(PlatformPermission.PLATFORM_IOC_INTEL_MANAGE)
    ),
) -> ExpireLapsedIocsResponse:
    expired_count = await svc.expire_lapsed_iocs(actor_roles=_PLATFORM_ROLES)
    _logger.info("ioc_expiry_sweep_completed", expired_count=expired_count)
    return ExpireLapsedIocsResponse(expired_count=expired_count)


# ── Lists (unambiguous, distinct paths — not part of the duplication fix) ────


@iocs_router.get("", response_model=PaginatedIocListResponse, summary="List this tenant's IOCs")
async def list_tenant_iocs(
    tenant_id: TenantIdDep,
    svc: IocServiceDep,
    lifecycle: str | None = Query(default=None),
    epistemic_state: str | None = Query(default=None),
    ioc_type: str | None = Query(default=None),
    search: str | None = Query(default=None, max_length=MAX_SEARCH_LENGTH),
    confidence: str | None = Query(default=None),
    source_system: str | None = Query(default=None, max_length=64),
    validity: str | None = Query(default=None),
    sort_by: str = Query(default=IocSortField.CREATED_AT.value),
    sort_dir: str = Query(default=SortDirection.DESC.value),
    limit: int = Query(default=DEFAULT_LIST_LIMIT, ge=1, le=MAX_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
    _tenant: TenantContext = Depends(require_permission(Permission.IOC_INTEL_READ)),
) -> PaginatedIocListResponse:
    items, total = await svc.list_iocs(
        ListIocsQuery(
            tenant_id=tenant_id,
            lifecycle=lifecycle,
            epistemic_state=epistemic_state,
            ioc_type=ioc_type,
            search=search,
            confidence=confidence,
            source_system=source_system,
            validity=validity,
            sort_by=sort_by,
            sort_dir=sort_dir,
            limit=limit,
            offset=offset,
            actor_roles=_TENANT_VIEWER_ROLES,
        )
    )
    summaries = [_summary_response(i) for i in items]
    return PaginatedIocListResponse(
        items=summaries, count=len(summaries), total=total, limit=limit, offset=offset
    )


@iocs_router.get("/global", response_model=PaginatedIocListResponse, summary="List global IOCs")
async def list_global_iocs(
    svc: IocServiceDep,
    lifecycle: str | None = Query(default=None),
    epistemic_state: str | None = Query(default=None),
    ioc_type: str | None = Query(default=None),
    search: str | None = Query(default=None, max_length=MAX_SEARCH_LENGTH),
    confidence: str | None = Query(default=None),
    source_system: str | None = Query(default=None, max_length=64),
    validity: str | None = Query(default=None),
    sort_by: str = Query(default=IocSortField.CREATED_AT.value),
    sort_dir: str = Query(default=SortDirection.DESC.value),
    limit: int = Query(default=DEFAULT_LIST_LIMIT, ge=1, le=MAX_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
    _platform: PlatformContext = Depends(
        require_platform_permission(PlatformPermission.PLATFORM_IOC_INTEL_READ)
    ),
) -> PaginatedIocListResponse:
    items, total = await svc.list_iocs(
        ListIocsQuery(
            tenant_id=None,
            lifecycle=lifecycle,
            epistemic_state=epistemic_state,
            ioc_type=ioc_type,
            search=search,
            confidence=confidence,
            source_system=source_system,
            validity=validity,
            sort_by=sort_by,
            sort_dir=sort_dir,
            limit=limit,
            offset=offset,
            actor_roles=_PLATFORM_ROLES,
        )
    )
    summaries = [_summary_response(i) for i in items]
    return PaginatedIocListResponse(
        items=summaries, count=len(summaries), total=total, limit=limit, offset=offset
    )


# ── Canonical single routes per {ioc_id} operation ──────────────────────────


@iocs_router.get("/{ioc_id}", response_model=IocDetailResponse, summary="Get an IOC")
async def get_ioc(
    ioc_id: str,
    svc: IocServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> IocDetailResponse:
    tenant_id = await _authorize_ioc_scope(
        ioc_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.IOC_INTEL_READ,
        platform_permission=PlatformPermission.PLATFORM_IOC_INTEL_READ,
    )
    dto = await svc.get_ioc(
        GetIocQuery(tenant_id=tenant_id, ioc_id=ioc_id, actor_roles=_actor_roles(tenant_id))
    )
    return _detail_response(dto)


@iocs_router.post(
    "/{ioc_id}/sources", response_model=IocDetailResponse, summary="Add a source attribution"
)
async def add_source(
    ioc_id: str,
    body: AddSourceAttributionRequest,
    svc: IocServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> IocDetailResponse:
    tenant_id = await _authorize_ioc_scope(
        ioc_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.IOC_INTEL_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_IOC_INTEL_MANAGE,
    )
    dto = await svc.add_source_attribution(
        AddSourceAttributionCommand(
            tenant_id=tenant_id,
            ioc_id=ioc_id,
            attribution=_to_attribution_input(body),
            actor_roles=_actor_roles(tenant_id),
        )
    )
    _log_mutation("ioc_source_attribution_added", ioc_id=dto.ioc_id, tenant_id=dto.tenant_id)
    return _detail_response(dto)


@iocs_router.post(
    "/{ioc_id}/evidence", response_model=IocDetailResponse, summary="Add an evidence citation"
)
async def add_evidence(
    ioc_id: str,
    body: AddEvidenceCitationRequest,
    svc: IocServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> IocDetailResponse:
    tenant_id = await _authorize_ioc_scope(
        ioc_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.IOC_INTEL_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_IOC_INTEL_MANAGE,
    )
    dto = await svc.add_evidence_citation(
        AddEvidenceCitationCommand(
            tenant_id=tenant_id,
            ioc_id=ioc_id,
            evidence_citation=body.citation.to_canonical_citation(),
            actor_roles=_actor_roles(tenant_id),
        )
    )
    _log_mutation("ioc_evidence_citation_added", ioc_id=dto.ioc_id, tenant_id=dto.tenant_id)
    return _detail_response(dto)


@iocs_router.patch(
    "/{ioc_id}/lifecycle", response_model=IocDetailResponse, summary="Transition IOC lifecycle"
)
async def transition_lifecycle(
    ioc_id: str,
    body: TransitionLifecycleRequest,
    svc: IocServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> IocDetailResponse:
    tenant_id = await _authorize_ioc_scope(
        ioc_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.IOC_INTEL_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_IOC_INTEL_MANAGE,
    )
    dto = await svc.transition_lifecycle(
        TransitionLifecycleCommand(
            tenant_id=tenant_id,
            ioc_id=ioc_id,
            target_lifecycle=body.target_lifecycle,
            actor_roles=_actor_roles(tenant_id),
        )
    )
    _log_mutation(
        "ioc_lifecycle_transitioned",
        ioc_id=dto.ioc_id,
        tenant_id=dto.tenant_id,
        target_lifecycle=body.target_lifecycle,
    )
    return _detail_response(dto)


@iocs_router.post(
    "/{ioc_id}/refresh", response_model=IocDetailResponse, summary="Refresh IOC validity"
)
async def refresh_ioc(
    ioc_id: str,
    svc: IocServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> IocDetailResponse:
    tenant_id = await _authorize_ioc_scope(
        ioc_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.IOC_INTEL_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_IOC_INTEL_MANAGE,
    )
    dto = await svc.refresh_validity(
        RefreshValidityCommand(
            tenant_id=tenant_id, ioc_id=ioc_id, actor_roles=_actor_roles(tenant_id)
        )
    )
    _log_mutation("ioc_refreshed", ioc_id=dto.ioc_id, tenant_id=dto.tenant_id)
    return _detail_response(dto)


@iocs_router.post(
    "/{ioc_id}/supersede", response_model=IocDetailResponse, summary="Supersede an IOC"
)
async def supersede_ioc(
    ioc_id: str,
    svc: IocServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> IocDetailResponse:
    tenant_id = await _authorize_ioc_scope(
        ioc_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.IOC_INTEL_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_IOC_INTEL_MANAGE,
    )
    dto = await svc.supersede_ioc(
        SupersedeIocCommand(tenant_id=tenant_id, ioc_id=ioc_id, actor_roles=_actor_roles(tenant_id))
    )
    _log_mutation("ioc_superseded", ioc_id=dto.ioc_id, tenant_id=dto.tenant_id)
    return _detail_response(dto)


@iocs_router.post("/{ioc_id}/revoke", response_model=IocDetailResponse, summary="Revoke an IOC")
async def revoke_ioc(
    ioc_id: str,
    svc: IocServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> IocDetailResponse:
    tenant_id = await _authorize_ioc_scope(
        ioc_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.IOC_INTEL_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_IOC_INTEL_MANAGE,
    )
    dto = await svc.revoke_ioc(
        RevokeIocCommand(tenant_id=tenant_id, ioc_id=ioc_id, actor_roles=_actor_roles(tenant_id))
    )
    _log_mutation("ioc_revoked", ioc_id=dto.ioc_id, tenant_id=dto.tenant_id)
    return _detail_response(dto)


@iocs_router.patch(
    "/{ioc_id}/epistemic-state",
    response_model=IocDetailResponse,
    summary="Transition IOC epistemic state",
)
async def transition_epistemic_state(
    ioc_id: str,
    body: TransitionEpistemicStateRequest,
    svc: IocServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> IocDetailResponse:
    tenant_id = await _authorize_ioc_scope(
        ioc_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.IOC_INTEL_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_IOC_INTEL_MANAGE,
    )
    dto = await svc.transition_epistemic_state(
        TransitionEpistemicStateCommand(
            tenant_id=tenant_id,
            ioc_id=ioc_id,
            target_state=body.target_state,
            actor_roles=_actor_roles(tenant_id),
        )
    )
    _log_mutation(
        "ioc_epistemic_transitioned",
        ioc_id=dto.ioc_id,
        tenant_id=dto.tenant_id,
        target_state=body.target_state,
    )
    return _detail_response(dto)


@iocs_router.post(
    "/{ioc_id}/dispute", response_model=IocDetailResponse, summary="Mark IOC disputed"
)
async def dispute_ioc(
    ioc_id: str,
    svc: IocServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> IocDetailResponse:
    tenant_id = await _authorize_ioc_scope(
        ioc_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.IOC_INTEL_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_IOC_INTEL_MANAGE,
    )
    dto = await svc.mark_disputed(
        MarkDisputedCommand(tenant_id=tenant_id, ioc_id=ioc_id, actor_roles=_actor_roles(tenant_id))
    )
    _log_mutation("ioc_disputed", ioc_id=dto.ioc_id, tenant_id=dto.tenant_id)
    return _detail_response(dto)


@iocs_router.post("/{ioc_id}/refute", response_model=IocDetailResponse, summary="Refute an IOC")
async def refute_ioc(
    ioc_id: str,
    body: RefuteIocRequest,
    svc: IocServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> IocDetailResponse:
    tenant_id = await _authorize_ioc_scope(
        ioc_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.IOC_INTEL_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_IOC_INTEL_MANAGE,
    )
    dto = await svc.refute_ioc(
        RefuteIocCommand(
            tenant_id=tenant_id,
            ioc_id=ioc_id,
            reason=body.reason,
            actor_roles=_actor_roles(tenant_id),
        )
    )
    # Deliberately does not log body.reason (free-text, potentially
    # sensitive analyst commentary) — only that a refute happened.
    _log_mutation("ioc_refuted", ioc_id=dto.ioc_id, tenant_id=dto.tenant_id)
    return _detail_response(dto)
