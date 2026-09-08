"""Intelligence Relationships API router (M51.4 Phase C1), mirroring
`attack_pattern_intel.api.v1.attack_patterns`'s exact ownership-based
authorization shape: `POST /observations/tenant` and
`POST /observations/global` remain two explicit routes (ownership must
be stated up front — no existing relationship to load yet); `GET /`
(tenant list) and `GET /global` (global list) are unambiguous,
non-duplicated paths; every `{relationship_id}` operation is ONE
canonical route, authorizing dynamically from the *loaded
relationship's own ownership scope*
(`IntelligenceRelationship.tenant_id`, resolved via
`IntelligenceRelationshipApplicationService.get_scope`) rather than
from which URL prefix the caller happened to use:

    scope = await svc.get_scope(relationship_id)  # TenantId | None; 404 if missing
    if scope is None:                              # global
        require platform.has_permission(...)       # else 403
    else:                                          # tenant-owned
        require tenant is not None and tenant.organization_id == str(scope)
                                                    # else 404 (cross-tenant)
        require tenant.has_permission(...)         # else 403
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, Query, Response, status

from intelligence_relationships.api.dependencies import (
    OptionalTenantContextDep,
    PlatformContextDep,
    RelationshipServiceDep,
    TenantIdDep,
)
from intelligence_relationships.api.schemas.relationship_schemas import (
    AddEvidenceCitationRequest,
    AddSourceAttributionRequest,
    EntityRefResponse,
    EvidenceCitationResponse,
    LifecycleTransitionRequest,
    ObserveRelationshipRequest,
    PaginatedRelationshipListResponse,
    RelationshipDetailResponse,
    RelationshipSummaryResponse,
    SourceAttributionRequest,
    SourceAttributionResponse,
    SupersedeRelationshipRequest,
    TransitionEpistemicStateRequest,
    VersionRecordResponse,
)
from intelligence_relationships.application.commands.relationship_commands import (
    AddEvidenceCitationCommand,
    AddSourceAttributionCommand,
    DeprecateRelationshipCommand,
    EntityRefInput,
    ObserveRelationshipCommand,
    ReactivateRelationshipCommand,
    RevokeRelationshipCommand,
    SourceAttributionInput,
    SupersedeRelationshipCommand,
    TransitionEpistemicStateCommand,
)
from intelligence_relationships.application.exceptions import (
    ApplicationForbiddenError,
    ApplicationNotFoundError,
)
from intelligence_relationships.application.queries.relationship_queries import (
    DEFAULT_LIST_LIMIT,
    MAX_LIST_LIMIT,
    GetRelationshipQuery,
    ListRelationshipsQuery,
)
from redforge.api.security import (
    TenantContext,
    require_permission,
    require_platform_permission,
)
from redforge.domain.identity.value_objects import Permission
from redforge.domain.platform_identity.value_objects import PlatformPermission

if TYPE_CHECKING:
    from intelligence_relationships.application.dtos.relationship_dtos import (
        RelationshipDetailDTO,
        RelationshipSummaryDTO,
    )
    from intelligence_relationships.application.services.relationship_application_service import (
        IntelligenceRelationshipApplicationService,
    )
    from intelligence_relationships.domain.value_objects.identifiers import TenantId
    from redforge.api.security import PlatformContext

relationships_router = APIRouter()


async def _authorize_scope(
    relationship_id: str,
    svc: IntelligenceRelationshipApplicationService,
    tenant: TenantContext | None,
    platform: PlatformContext,
    *,
    tenant_permission: Permission,
    platform_permission: PlatformPermission,
) -> TenantId | None:
    """The single ownership-based authorization decision every
    canonical `{relationship_id}` route uses. Raises
    `ApplicationNotFoundError` (404) if the relationship doesn't exist,
    `ApplicationForbiddenError` (403) if the caller lacks the required
    authority for the resource's actual scope, or returns the
    `tenant_id` to use for the real, authorized operation (`None` for
    global)."""
    scope = await svc.get_scope(relationship_id)
    if scope is None:
        if not platform.has_permission(platform_permission):
            raise ApplicationForbiddenError(platform_permission.value)
        return None
    if tenant is None or tenant.organization_id != str(scope):
        raise ApplicationNotFoundError("IntelligenceRelationship", relationship_id)
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


def _observe_command(
    body: ObserveRelationshipRequest, tenant_id: TenantId | None
) -> ObserveRelationshipCommand:
    return ObserveRelationshipCommand(
        tenant_id=tenant_id,
        relationship_type=body.relationship_type,
        source_entity=EntityRefInput(
            entity_type=body.source_entity.entity_type,
            entity_id=body.source_entity.entity_id,
        ),
        target_entity=EntityRefInput(
            entity_type=body.target_entity.entity_type,
            entity_id=body.target_entity.entity_id,
        ),
        direction=body.direction,
        confidence=body.confidence,
        epistemic_state=body.epistemic_state,
        valid_from=body.valid_from,
        valid_until=body.valid_until,
        evidence_citations=tuple(body.evidence_citations),
        source_attributions=tuple(_to_attribution_input(a) for a in body.source_attributions),
    )


def _detail_response(dto: RelationshipDetailDTO) -> RelationshipDetailResponse:
    return RelationshipDetailResponse(
        relationship_id=dto.relationship_id,
        tenant_id=dto.tenant_id,
        relationship_type=dto.relationship_type,
        source_entity=EntityRefResponse(
            entity_type=dto.source_entity.entity_type,
            entity_id=dto.source_entity.entity_id,
        ),
        target_entity=EntityRefResponse(
            entity_type=dto.target_entity.entity_type,
            entity_id=dto.target_entity.entity_id,
        ),
        direction=dto.direction,
        confidence=dto.confidence,
        epistemic_state=dto.epistemic_state,
        lifecycle_status=dto.lifecycle_status,
        superseded_by=dto.superseded_by,
        valid_from=dto.valid_from,
        valid_until=dto.valid_until,
        created_at=dto.created_at,
        updated_at=dto.updated_at,
        evidence_citations=[
            EvidenceCitationResponse(value=c.value) for c in dto.evidence_citations
        ],
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


def _summary_response(dto: RelationshipSummaryDTO) -> RelationshipSummaryResponse:
    return RelationshipSummaryResponse(
        relationship_id=dto.relationship_id,
        tenant_id=dto.tenant_id,
        relationship_type=dto.relationship_type,
        source_entity=EntityRefResponse(
            entity_type=dto.source_entity.entity_type,
            entity_id=dto.source_entity.entity_id,
        ),
        target_entity=EntityRefResponse(
            entity_type=dto.target_entity.entity_type,
            entity_id=dto.target_entity.entity_id,
        ),
        direction=dto.direction,
        confidence=dto.confidence,
        epistemic_state=dto.epistemic_state,
        lifecycle_status=dto.lifecycle_status,
        created_at=dto.created_at,
        updated_at=dto.updated_at,
        evidence_citation_count=dto.evidence_citation_count,
        source_attribution_count=dto.source_attribution_count,
    )


# ── Observation (ownership stated explicitly — no existing relationship to load) ──


@relationships_router.post(
    "/observations/tenant",
    status_code=status.HTTP_201_CREATED,
    response_model=RelationshipDetailResponse,
    summary="Observe a tenant-scoped IntelligenceRelationship",
    description=(
        "Tenant-scoped relationship observation. The relationship type must "
        "match the exact (source, target) entity-type pairing it requires, and "
        "IOC/threat-actor/attack-pattern endpoints must already exist in their "
        "owning bounded context. Deduplicates against any existing relationship "
        "for this tenant with the same type and endpoints."
    ),
)
async def observe_tenant_relationship(
    body: ObserveRelationshipRequest,
    response: Response,
    tenant_id: TenantIdDep,
    svc: RelationshipServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.RELATIONSHIP_OBSERVE)),
) -> RelationshipDetailResponse:
    dto = await svc.observe(_observe_command(body, tenant_id))
    response.headers["Location"] = f"/api/v1/relationships/{dto.relationship_id}"
    return _detail_response(dto)


@relationships_router.post(
    "/observations/global",
    status_code=status.HTTP_201_CREATED,
    response_model=RelationshipDetailResponse,
    summary="Observe a global IntelligenceRelationship (platform authority required)",
    description=(
        "Global, RedForge-curated relationship. Requires platform authority "
        "(PLATFORM_RELATIONSHIP_MANAGE) — no organization OWNER/ADMIN/"
        "SECURITY_MANAGER membership satisfies this."
    ),
)
async def observe_global_relationship(
    body: ObserveRelationshipRequest,
    response: Response,
    svc: RelationshipServiceDep,
    _platform: PlatformContext = Depends(
        require_platform_permission(PlatformPermission.PLATFORM_RELATIONSHIP_MANAGE)
    ),
) -> RelationshipDetailResponse:
    dto = await svc.observe(_observe_command(body, None))
    response.headers["Location"] = f"/api/v1/relationships/{dto.relationship_id}"
    return _detail_response(dto)


# ── Lists (unambiguous, distinct paths) ─────────────────────────────────────


@relationships_router.get(
    "",
    response_model=PaginatedRelationshipListResponse,
    summary="List this tenant's IntelligenceRelationships",
)
async def list_tenant_relationships(
    tenant_id: TenantIdDep,
    svc: RelationshipServiceDep,
    relationship_type: str | None = Query(default=None),
    lifecycle_status: str | None = Query(default=None),
    epistemic_state: str | None = Query(default=None),
    source_entity_id: str | None = Query(default=None),
    target_entity_id: str | None = Query(default=None),
    limit: int = Query(default=DEFAULT_LIST_LIMIT, ge=1, le=MAX_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
    _tenant: TenantContext = Depends(require_permission(Permission.RELATIONSHIP_READ)),
) -> PaginatedRelationshipListResponse:
    items = await svc.list(
        ListRelationshipsQuery(
            tenant_id=tenant_id,
            relationship_type=relationship_type,
            lifecycle_status=lifecycle_status,
            epistemic_state=epistemic_state,
            source_entity_id=source_entity_id,
            target_entity_id=target_entity_id,
            limit=limit,
            offset=offset,
        )
    )
    summaries = [_summary_response(i) for i in items]
    return PaginatedRelationshipListResponse(
        items=summaries, count=len(summaries), limit=limit, offset=offset
    )


@relationships_router.get(
    "/global",
    response_model=PaginatedRelationshipListResponse,
    summary="List global IntelligenceRelationships",
)
async def list_global_relationships(
    svc: RelationshipServiceDep,
    relationship_type: str | None = Query(default=None),
    lifecycle_status: str | None = Query(default=None),
    epistemic_state: str | None = Query(default=None),
    source_entity_id: str | None = Query(default=None),
    target_entity_id: str | None = Query(default=None),
    limit: int = Query(default=DEFAULT_LIST_LIMIT, ge=1, le=MAX_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
    _platform: PlatformContext = Depends(
        require_platform_permission(PlatformPermission.PLATFORM_RELATIONSHIP_READ)
    ),
) -> PaginatedRelationshipListResponse:
    items = await svc.list(
        ListRelationshipsQuery(
            tenant_id=None,
            relationship_type=relationship_type,
            lifecycle_status=lifecycle_status,
            epistemic_state=epistemic_state,
            source_entity_id=source_entity_id,
            target_entity_id=target_entity_id,
            limit=limit,
            offset=offset,
        )
    )
    summaries = [_summary_response(i) for i in items]
    return PaginatedRelationshipListResponse(
        items=summaries, count=len(summaries), limit=limit, offset=offset
    )


# ── Canonical single routes per {relationship_id} operation ────────────────


@relationships_router.get(
    "/{relationship_id}",
    response_model=RelationshipDetailResponse,
    summary="Get an IntelligenceRelationship",
)
async def get_relationship(
    relationship_id: str,
    svc: RelationshipServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> RelationshipDetailResponse:
    tenant_id = await _authorize_scope(
        relationship_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.RELATIONSHIP_READ,
        platform_permission=PlatformPermission.PLATFORM_RELATIONSHIP_READ,
    )
    dto = await svc.get(GetRelationshipQuery(tenant_id=tenant_id, relationship_id=relationship_id))
    return _detail_response(dto)


@relationships_router.post(
    "/{relationship_id}/evidence-citations",
    response_model=RelationshipDetailResponse,
    summary="Add an evidence citation",
)
async def add_evidence_citation(
    relationship_id: str,
    body: AddEvidenceCitationRequest,
    svc: RelationshipServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> RelationshipDetailResponse:
    tenant_id = await _authorize_scope(
        relationship_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.RELATIONSHIP_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_RELATIONSHIP_MANAGE,
    )
    dto = await svc.add_evidence_citation(
        AddEvidenceCitationCommand(
            tenant_id=tenant_id, relationship_id=relationship_id, value=body.value
        )
    )
    return _detail_response(dto)


@relationships_router.post(
    "/{relationship_id}/source-attributions",
    response_model=RelationshipDetailResponse,
    summary="Add a source attribution",
)
async def add_source_attribution(
    relationship_id: str,
    body: AddSourceAttributionRequest,
    svc: RelationshipServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> RelationshipDetailResponse:
    tenant_id = await _authorize_scope(
        relationship_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.RELATIONSHIP_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_RELATIONSHIP_MANAGE,
    )
    dto = await svc.add_source_attribution(
        AddSourceAttributionCommand(
            tenant_id=tenant_id,
            relationship_id=relationship_id,
            attribution=_to_attribution_input(body.attribution),
        )
    )
    return _detail_response(dto)


@relationships_router.patch(
    "/{relationship_id}/epistemic-state",
    response_model=RelationshipDetailResponse,
    summary="Transition the epistemic state of a relationship claim",
)
async def transition_epistemic_state(
    relationship_id: str,
    body: TransitionEpistemicStateRequest,
    svc: RelationshipServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> RelationshipDetailResponse:
    tenant_id = await _authorize_scope(
        relationship_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.RELATIONSHIP_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_RELATIONSHIP_MANAGE,
    )
    dto = await svc.transition_epistemic_state(
        TransitionEpistemicStateCommand(
            tenant_id=tenant_id,
            relationship_id=relationship_id,
            target_state=body.target_state,
            evidence=_to_attribution_input(body.evidence),
        )
    )
    return _detail_response(dto)


@relationships_router.patch(
    "/{relationship_id}/deprecate",
    response_model=RelationshipDetailResponse,
    summary="Deprecate an IntelligenceRelationship",
)
async def deprecate_relationship(
    relationship_id: str,
    body: LifecycleTransitionRequest,
    svc: RelationshipServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> RelationshipDetailResponse:
    tenant_id = await _authorize_scope(
        relationship_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.RELATIONSHIP_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_RELATIONSHIP_MANAGE,
    )
    dto = await svc.deprecate(
        DeprecateRelationshipCommand(
            tenant_id=tenant_id,
            relationship_id=relationship_id,
            evidence=_to_attribution_input(body.evidence),
        )
    )
    return _detail_response(dto)


@relationships_router.patch(
    "/{relationship_id}/revoke",
    response_model=RelationshipDetailResponse,
    summary="Revoke an IntelligenceRelationship",
)
async def revoke_relationship(
    relationship_id: str,
    body: LifecycleTransitionRequest,
    svc: RelationshipServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> RelationshipDetailResponse:
    tenant_id = await _authorize_scope(
        relationship_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.RELATIONSHIP_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_RELATIONSHIP_MANAGE,
    )
    dto = await svc.revoke(
        RevokeRelationshipCommand(
            tenant_id=tenant_id,
            relationship_id=relationship_id,
            evidence=_to_attribution_input(body.evidence),
        )
    )
    return _detail_response(dto)


@relationships_router.patch(
    "/{relationship_id}/supersede",
    response_model=RelationshipDetailResponse,
    summary="Supersede an IntelligenceRelationship",
)
async def supersede_relationship(
    relationship_id: str,
    body: SupersedeRelationshipRequest,
    svc: RelationshipServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> RelationshipDetailResponse:
    tenant_id = await _authorize_scope(
        relationship_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.RELATIONSHIP_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_RELATIONSHIP_MANAGE,
    )
    dto = await svc.supersede(
        SupersedeRelationshipCommand(
            tenant_id=tenant_id,
            relationship_id=relationship_id,
            superseded_by=body.superseded_by,
            evidence=_to_attribution_input(body.evidence),
        )
    )
    return _detail_response(dto)


@relationships_router.patch(
    "/{relationship_id}/reactivate",
    response_model=RelationshipDetailResponse,
    summary="Reactivate an IntelligenceRelationship",
)
async def reactivate_relationship(
    relationship_id: str,
    body: LifecycleTransitionRequest,
    svc: RelationshipServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> RelationshipDetailResponse:
    tenant_id = await _authorize_scope(
        relationship_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.RELATIONSHIP_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_RELATIONSHIP_MANAGE,
    )
    dto = await svc.reactivate(
        ReactivateRelationshipCommand(
            tenant_id=tenant_id,
            relationship_id=relationship_id,
            evidence=_to_attribution_input(body.evidence),
        )
    )
    return _detail_response(dto)
