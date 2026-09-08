"""AttackPattern Intelligence API router (M51.3 Phase B1), mirroring
`ioc_intelligence.api.v1.iocs`'s exact ownership-based authorization
shape: `POST /observations/tenant` and `POST /observations/global`
remain two explicit routes (ownership must be stated up front — no
existing AttackPattern to load yet); `GET /` (tenant list) and
`GET /global` (global list) are unambiguous, non-duplicated paths;
every `{attack_pattern_id}` operation is ONE canonical route,
authorizing dynamically from the *loaded AttackPattern's own
ownership scope* (`AttackPattern.tenant_id`, resolved via
`AttackPatternApplicationService.get_scope`) rather than from which
URL prefix the caller happened to use — the same decision tree
`ioc_intelligence`'s Phase A4.1 correction established:

    scope = await svc.get_scope(attack_pattern_id)  # TenantId | None; 404 if missing
    if scope is None:                                 # global
        require platform.has_permission(...)          # else 403
    else:                                              # tenant-owned
        require tenant is not None and tenant.organization_id == str(scope)
                                                        # else 404 (cross-tenant)
        require tenant.has_permission(...)             # else 403
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, Query, Response, status

from attack_pattern_intel.api.dependencies import (
    AttackPatternServiceDep,
    OptionalTenantContextDep,
    PlatformContextDep,
    TenantIdDep,
)
from attack_pattern_intel.api.schemas.attack_pattern_schemas import (
    AddDetectionGuidanceRequest,
    AddMitigationReferenceRequest,
    AddProcedureExampleRequest,
    AddRelationshipRequest,
    AttackPatternDetailResponse,
    AttackPatternSummaryResponse,
    DetectionGuidanceResponse,
    LifecycleTransitionRequest,
    MitigationReferenceResponse,
    ObserveAttackPatternRequest,
    PaginatedAttackPatternListResponse,
    ProcedureExampleResponse,
    RelationshipMetadataResponse,
    SourceAttributionRequest,
    SourceAttributionResponse,
    SupersedeAttackPatternRequest,
    TacticMappingResponse,
    VersionRecordResponse,
)
from attack_pattern_intel.application.commands.attack_pattern_commands import (
    AddDetectionGuidanceCommand,
    AddMitigationReferenceCommand,
    AddProcedureExampleCommand,
    AddRelationshipCommand,
    DeprecateAttackPatternCommand,
    ObserveAttackPatternCommand,
    ReactivateAttackPatternCommand,
    RevokeAttackPatternCommand,
    SourceAttributionInput,
    SupersedeAttackPatternCommand,
    TacticMappingInput,
)
from attack_pattern_intel.application.exceptions import (
    ApplicationForbiddenError,
    ApplicationNotFoundError,
)
from attack_pattern_intel.application.queries.attack_pattern_queries import (
    DEFAULT_LIST_LIMIT,
    MAX_LIST_LIMIT,
    GetAttackPatternQuery,
    ListAttackPatternsQuery,
)
from redforge.api.security import (
    TenantContext,
    require_permission,
    require_platform_permission,
)
from redforge.domain.identity.value_objects import Permission
from redforge.domain.platform_identity.value_objects import PlatformPermission

if TYPE_CHECKING:
    from attack_pattern_intel.application.dtos.attack_pattern_dtos import (
        AttackPatternDetailDTO,
        AttackPatternSummaryDTO,
    )
    from attack_pattern_intel.application.services.attack_pattern_application_service import (
        AttackPatternApplicationService,
    )
    from attack_pattern_intel.domain.value_objects.identifiers import TenantId
    from redforge.api.security import PlatformContext

attack_patterns_router = APIRouter()


async def _authorize_scope(
    attack_pattern_id: str,
    svc: AttackPatternApplicationService,
    tenant: TenantContext | None,
    platform: PlatformContext,
    *,
    tenant_permission: Permission,
    platform_permission: PlatformPermission,
) -> TenantId | None:
    """The single ownership-based authorization decision every
    canonical `{attack_pattern_id}` route uses. Raises
    `ApplicationNotFoundError` (404) if the AttackPattern doesn't
    exist, `ApplicationForbiddenError` (403) if the caller lacks the
    required authority for the resource's actual scope, or returns the
    `tenant_id` to use for the real, authorized operation (`None` for
    global)."""
    scope = await svc.get_scope(attack_pattern_id)
    if scope is None:
        if not platform.has_permission(platform_permission):
            raise ApplicationForbiddenError(platform_permission.value)
        return None
    if tenant is None or tenant.organization_id != str(scope):
        raise ApplicationNotFoundError("AttackPattern", attack_pattern_id)
    if not tenant.has_permission(tenant_permission):
        raise ApplicationForbiddenError(tenant_permission.value)
    return scope


def _to_attribution_input(attribution: SourceAttributionRequest) -> SourceAttributionInput:
    return SourceAttributionInput(
        source_system=attribution.source_system,
        reference=attribution.reference,
        observed_at=attribution.observed_at,
        notes=attribution.notes,
    )


def _detail_response(dto: AttackPatternDetailDTO) -> AttackPatternDetailResponse:
    return AttackPatternDetailResponse(
        attack_pattern_id=dto.attack_pattern_id,
        tenant_id=dto.tenant_id,
        technique_id=dto.technique_id,
        sub_technique_id=dto.sub_technique_id,
        lifecycle_status=dto.lifecycle_status,
        superseded_by=dto.superseded_by,
        created_at=dto.created_at,
        updated_at=dto.updated_at,
        tactic_mappings=[
            TacticMappingResponse(
                tactic_id=t.tactic_id,
                tactic_shortname=t.tactic_shortname,
                priority=t.priority,
                notes=t.notes,
            )
            for t in dto.tactic_mappings
        ],
        platforms=list(dto.platforms),
        detection_guidance=[
            DetectionGuidanceResponse(
                content=g.content,
                attribution=SourceAttributionResponse(
                    source_system=g.attribution.source_system,
                    reference=g.attribution.reference,
                    observed_at=g.attribution.observed_at,
                    notes=g.attribution.notes,
                ),
            )
            for g in dto.detection_guidance
        ],
        mitigation_references=[
            MitigationReferenceResponse(
                mitigation_id=m.mitigation_id,
                name=m.name,
                description=m.description,
                attribution=SourceAttributionResponse(
                    source_system=m.attribution.source_system,
                    reference=m.attribution.reference,
                    observed_at=m.attribution.observed_at,
                    notes=m.attribution.notes,
                ),
            )
            for m in dto.mitigation_references
        ],
        procedure_examples=[
            ProcedureExampleResponse(
                description=p.description,
                actor_ref=p.actor_ref,
                attribution=SourceAttributionResponse(
                    source_system=p.attribution.source_system,
                    reference=p.attribution.reference,
                    observed_at=p.attribution.observed_at,
                    notes=p.attribution.notes,
                ),
            )
            for p in dto.procedure_examples
        ],
        relationship_metadata=[
            RelationshipMetadataResponse(
                relationship_type=r.relationship_type,
                target_attack_pattern_id=r.target_attack_pattern_id,
                attribution=SourceAttributionResponse(
                    source_system=r.attribution.source_system,
                    reference=r.attribution.reference,
                    observed_at=r.attribution.observed_at,
                    notes=r.attribution.notes,
                ),
            )
            for r in dto.relationship_metadata
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


def _summary_response(dto: AttackPatternSummaryDTO) -> AttackPatternSummaryResponse:
    return AttackPatternSummaryResponse(
        attack_pattern_id=dto.attack_pattern_id,
        tenant_id=dto.tenant_id,
        technique_id=dto.technique_id,
        sub_technique_id=dto.sub_technique_id,
        lifecycle_status=dto.lifecycle_status,
        created_at=dto.created_at,
        updated_at=dto.updated_at,
        guidance_count=dto.guidance_count,
        mitigation_count=dto.mitigation_count,
        procedure_example_count=dto.procedure_example_count,
    )


# ── Observation (ownership stated explicitly — no existing AttackPattern to load) ──


@attack_patterns_router.post(
    "/observations/tenant",
    status_code=status.HTTP_201_CREATED,
    response_model=AttackPatternDetailResponse,
    summary="Observe a tenant-scoped AttackPattern",
    description=(
        "Tenant-scoped AttackPattern observation. `technique_id` must already "
        "exist in the canonical threat_intel MITRE ATT&CK catalog. Deduplicates "
        "against any existing AttackPattern for this tenant with the same "
        "technique/sub-technique — never creates a second identity."
    ),
)
async def observe_tenant_attack_pattern(
    body: ObserveAttackPatternRequest,
    response: Response,
    tenant_id: TenantIdDep,
    svc: AttackPatternServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ATTACK_PATTERN_OBSERVE)),
) -> AttackPatternDetailResponse:
    dto = await svc.observe(
        ObserveAttackPatternCommand(
            tenant_id=tenant_id,
            technique_id=body.technique_id,
            sub_technique_id=body.sub_technique_id,
            tactic_mappings=tuple(
                TacticMappingInput(
                    tactic_id=t.tactic_id,
                    tactic_shortname=t.tactic_shortname,
                    priority=t.priority,
                    notes=t.notes,
                )
                for t in body.tactic_mappings
            ),
            platforms=tuple(body.platforms),
        )
    )
    response.headers["Location"] = f"/api/v1/attack-patterns/{dto.attack_pattern_id}"
    return _detail_response(dto)


@attack_patterns_router.post(
    "/observations/global",
    status_code=status.HTTP_201_CREATED,
    response_model=AttackPatternDetailResponse,
    summary="Observe a global AttackPattern (platform authority required)",
    description=(
        "Global, RedForge-curated AttackPattern. Requires platform authority "
        "(PLATFORM_ATTACK_PATTERN_MANAGE) — no organization OWNER/ADMIN/"
        "SECURITY_MANAGER membership satisfies this."
    ),
)
async def observe_global_attack_pattern(
    body: ObserveAttackPatternRequest,
    response: Response,
    svc: AttackPatternServiceDep,
    _platform: PlatformContext = Depends(
        require_platform_permission(PlatformPermission.PLATFORM_ATTACK_PATTERN_MANAGE)
    ),
) -> AttackPatternDetailResponse:
    dto = await svc.observe(
        ObserveAttackPatternCommand(
            tenant_id=None,
            technique_id=body.technique_id,
            sub_technique_id=body.sub_technique_id,
            tactic_mappings=tuple(
                TacticMappingInput(
                    tactic_id=t.tactic_id,
                    tactic_shortname=t.tactic_shortname,
                    priority=t.priority,
                    notes=t.notes,
                )
                for t in body.tactic_mappings
            ),
            platforms=tuple(body.platforms),
        )
    )
    response.headers["Location"] = f"/api/v1/attack-patterns/{dto.attack_pattern_id}"
    return _detail_response(dto)


# ── Lists (unambiguous, distinct paths) ─────────────────────────────────────


@attack_patterns_router.get(
    "",
    response_model=PaginatedAttackPatternListResponse,
    summary="List this tenant's AttackPatterns",
)
async def list_tenant_attack_patterns(
    tenant_id: TenantIdDep,
    svc: AttackPatternServiceDep,
    lifecycle_status: str | None = Query(default=None),
    tactic_id: str | None = Query(default=None),
    platform: str | None = Query(default=None),
    limit: int = Query(default=DEFAULT_LIST_LIMIT, ge=1, le=MAX_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
    _tenant: TenantContext = Depends(require_permission(Permission.ATTACK_PATTERN_READ)),
) -> PaginatedAttackPatternListResponse:
    items = await svc.list(
        ListAttackPatternsQuery(
            tenant_id=tenant_id,
            lifecycle_status=lifecycle_status,
            tactic_id=tactic_id,
            platform=platform,
            limit=limit,
            offset=offset,
        )
    )
    summaries = [_summary_response(i) for i in items]
    return PaginatedAttackPatternListResponse(
        items=summaries, count=len(summaries), limit=limit, offset=offset
    )


@attack_patterns_router.get(
    "/global",
    response_model=PaginatedAttackPatternListResponse,
    summary="List global AttackPatterns",
)
async def list_global_attack_patterns(
    svc: AttackPatternServiceDep,
    lifecycle_status: str | None = Query(default=None),
    tactic_id: str | None = Query(default=None),
    platform: str | None = Query(default=None),
    limit: int = Query(default=DEFAULT_LIST_LIMIT, ge=1, le=MAX_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
    _platform: PlatformContext = Depends(
        require_platform_permission(PlatformPermission.PLATFORM_ATTACK_PATTERN_READ)
    ),
) -> PaginatedAttackPatternListResponse:
    items = await svc.list(
        ListAttackPatternsQuery(
            tenant_id=None,
            lifecycle_status=lifecycle_status,
            tactic_id=tactic_id,
            platform=platform,
            limit=limit,
            offset=offset,
        )
    )
    summaries = [_summary_response(i) for i in items]
    return PaginatedAttackPatternListResponse(
        items=summaries, count=len(summaries), limit=limit, offset=offset
    )


# ── Canonical single routes per {attack_pattern_id} operation ──────────────


@attack_patterns_router.get(
    "/{attack_pattern_id}",
    response_model=AttackPatternDetailResponse,
    summary="Get an AttackPattern",
)
async def get_attack_pattern(
    attack_pattern_id: str,
    svc: AttackPatternServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> AttackPatternDetailResponse:
    tenant_id = await _authorize_scope(
        attack_pattern_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.ATTACK_PATTERN_READ,
        platform_permission=PlatformPermission.PLATFORM_ATTACK_PATTERN_READ,
    )
    dto = await svc.get(
        GetAttackPatternQuery(tenant_id=tenant_id, attack_pattern_id=attack_pattern_id)
    )
    return _detail_response(dto)


@attack_patterns_router.post(
    "/{attack_pattern_id}/detection-guidance",
    response_model=AttackPatternDetailResponse,
    summary="Add detection guidance",
)
async def add_detection_guidance(
    attack_pattern_id: str,
    body: AddDetectionGuidanceRequest,
    svc: AttackPatternServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> AttackPatternDetailResponse:
    tenant_id = await _authorize_scope(
        attack_pattern_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.ATTACK_PATTERN_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_ATTACK_PATTERN_MANAGE,
    )
    dto = await svc.add_detection_guidance(
        AddDetectionGuidanceCommand(
            tenant_id=tenant_id,
            attack_pattern_id=attack_pattern_id,
            content=body.content,
            attribution=_to_attribution_input(body.attribution),
        )
    )
    return _detail_response(dto)


@attack_patterns_router.post(
    "/{attack_pattern_id}/mitigation-references",
    response_model=AttackPatternDetailResponse,
    summary="Add a mitigation reference",
)
async def add_mitigation_reference(
    attack_pattern_id: str,
    body: AddMitigationReferenceRequest,
    svc: AttackPatternServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> AttackPatternDetailResponse:
    tenant_id = await _authorize_scope(
        attack_pattern_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.ATTACK_PATTERN_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_ATTACK_PATTERN_MANAGE,
    )
    dto = await svc.add_mitigation_reference(
        AddMitigationReferenceCommand(
            tenant_id=tenant_id,
            attack_pattern_id=attack_pattern_id,
            mitigation_id=body.mitigation_id,
            name=body.name,
            description=body.description,
            attribution=_to_attribution_input(body.attribution),
        )
    )
    return _detail_response(dto)


@attack_patterns_router.post(
    "/{attack_pattern_id}/procedure-examples",
    response_model=AttackPatternDetailResponse,
    summary="Add a procedure example",
)
async def add_procedure_example(
    attack_pattern_id: str,
    body: AddProcedureExampleRequest,
    svc: AttackPatternServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> AttackPatternDetailResponse:
    tenant_id = await _authorize_scope(
        attack_pattern_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.ATTACK_PATTERN_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_ATTACK_PATTERN_MANAGE,
    )
    dto = await svc.add_procedure_example(
        AddProcedureExampleCommand(
            tenant_id=tenant_id,
            attack_pattern_id=attack_pattern_id,
            description=body.description,
            actor_ref=body.actor_ref,
            attribution=_to_attribution_input(body.attribution),
        )
    )
    return _detail_response(dto)


@attack_patterns_router.post(
    "/{attack_pattern_id}/relationships",
    response_model=AttackPatternDetailResponse,
    summary="Add relationship metadata",
)
async def add_relationship(
    attack_pattern_id: str,
    body: AddRelationshipRequest,
    svc: AttackPatternServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> AttackPatternDetailResponse:
    tenant_id = await _authorize_scope(
        attack_pattern_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.ATTACK_PATTERN_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_ATTACK_PATTERN_MANAGE,
    )
    dto = await svc.add_relationship(
        AddRelationshipCommand(
            tenant_id=tenant_id,
            attack_pattern_id=attack_pattern_id,
            relationship_type=body.relationship_type,
            target_attack_pattern_id=body.target_attack_pattern_id,
            attribution=_to_attribution_input(body.attribution),
        )
    )
    return _detail_response(dto)


@attack_patterns_router.patch(
    "/{attack_pattern_id}/deprecate",
    response_model=AttackPatternDetailResponse,
    summary="Deprecate an AttackPattern",
)
async def deprecate_attack_pattern(
    attack_pattern_id: str,
    body: LifecycleTransitionRequest,
    svc: AttackPatternServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> AttackPatternDetailResponse:
    tenant_id = await _authorize_scope(
        attack_pattern_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.ATTACK_PATTERN_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_ATTACK_PATTERN_MANAGE,
    )
    dto = await svc.deprecate(
        DeprecateAttackPatternCommand(
            tenant_id=tenant_id,
            attack_pattern_id=attack_pattern_id,
            evidence=_to_attribution_input(body.evidence),
        )
    )
    return _detail_response(dto)


@attack_patterns_router.patch(
    "/{attack_pattern_id}/revoke",
    response_model=AttackPatternDetailResponse,
    summary="Revoke an AttackPattern",
)
async def revoke_attack_pattern(
    attack_pattern_id: str,
    body: LifecycleTransitionRequest,
    svc: AttackPatternServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> AttackPatternDetailResponse:
    tenant_id = await _authorize_scope(
        attack_pattern_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.ATTACK_PATTERN_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_ATTACK_PATTERN_MANAGE,
    )
    dto = await svc.revoke(
        RevokeAttackPatternCommand(
            tenant_id=tenant_id,
            attack_pattern_id=attack_pattern_id,
            evidence=_to_attribution_input(body.evidence),
        )
    )
    return _detail_response(dto)


@attack_patterns_router.patch(
    "/{attack_pattern_id}/supersede",
    response_model=AttackPatternDetailResponse,
    summary="Supersede an AttackPattern",
)
async def supersede_attack_pattern(
    attack_pattern_id: str,
    body: SupersedeAttackPatternRequest,
    svc: AttackPatternServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> AttackPatternDetailResponse:
    tenant_id = await _authorize_scope(
        attack_pattern_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.ATTACK_PATTERN_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_ATTACK_PATTERN_MANAGE,
    )
    dto = await svc.supersede(
        SupersedeAttackPatternCommand(
            tenant_id=tenant_id,
            attack_pattern_id=attack_pattern_id,
            superseded_by=body.superseded_by,
            evidence=_to_attribution_input(body.evidence),
        )
    )
    return _detail_response(dto)


@attack_patterns_router.patch(
    "/{attack_pattern_id}/reactivate",
    response_model=AttackPatternDetailResponse,
    summary="Reactivate an AttackPattern",
)
async def reactivate_attack_pattern(
    attack_pattern_id: str,
    body: LifecycleTransitionRequest,
    svc: AttackPatternServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> AttackPatternDetailResponse:
    tenant_id = await _authorize_scope(
        attack_pattern_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.ATTACK_PATTERN_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_ATTACK_PATTERN_MANAGE,
    )
    dto = await svc.reactivate(
        ReactivateAttackPatternCommand(
            tenant_id=tenant_id,
            attack_pattern_id=attack_pattern_id,
            evidence=_to_attribution_input(body.evidence),
        )
    )
    return _detail_response(dto)
