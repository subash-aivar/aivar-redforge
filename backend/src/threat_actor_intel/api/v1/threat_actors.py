"""ThreatActor + ThreatActorAssociation API router (M51.1 Phase 4).

Endpoint set is bounded strictly by what `ThreatActorApplicationService`
already exposes (Phase 2/3, certified) — no endpoint here invents a
capability the application layer does not already have. Every handler
does exactly one thing: authorize via `require_permission`, build a
command/query with `tenant_id` from the trusted `TenantIdDep` (never
from the request body), call the service, map the DTO to a response
model. No repository/session access, no business logic, no domain
object crosses this boundary.
"""

from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, Depends, Query, Response, status

from redforge.api.security import TenantContext, require_permission
from redforge.domain.identity.value_objects import Permission
from threat_actor_intel.api.dependencies import TenantIdDep, ThreatActorServiceDep
from threat_actor_intel.api.schemas.threat_actor_schemas import (
    AddAliasRequest,
    AssociateIndicatorRequest,
    AssociateTechniqueRequest,
    CreateAssociationRequest,
    ListThreatActorAssociationsResponse,
    ListThreatActorsResponse,
    RegisterThreatActorRequest,
    ThreatActorAssociationResponse,
    ThreatActorDetailResponse,
    ThreatActorSummaryResponse,
    TransitionStatusRequest,
    UpdateMotivationRequest,
    UpdateSophisticationRequest,
)
from threat_actor_intel.application.commands.threat_actor_commands import (
    AddAliasCommand,
    AssociateIndicatorCommand,
    AssociateTechniqueCommand,
    CreateThreatActorAssociationCommand,
    RegisterThreatActorCommand,
    RetractThreatActorAssociationCommand,
    TransitionActivityStatusCommand,
    UpdateMotivationsCommand,
    UpdateSophisticationCommand,
)
from threat_actor_intel.application.dtos.threat_actor_dtos import (
    ThreatActorAssociationDTO,
    ThreatActorDetailDTO,
)
from threat_actor_intel.application.queries.threat_actor_queries import (
    GetThreatActorQuery,
    ListAssociationsForTenantQuery,
    ListThreatActorsQuery,
)
from threat_actor_intel.domain.value_objects.enums import ThreatActorIntelRole

threat_actors_router = APIRouter()

_ADMIN_ROLES = (ThreatActorIntelRole.PLATFORM_ADMIN.value,)
_ANALYST_ROLES = (ThreatActorIntelRole.ANALYST.value,)
_VIEWER_ROLES = (ThreatActorIntelRole.VIEWER.value,)


def _detail_response(dto: ThreatActorDetailDTO) -> ThreatActorDetailResponse:
    return ThreatActorDetailResponse.model_validate(asdict(dto))


def _association_response(dto: ThreatActorAssociationDTO) -> ThreatActorAssociationResponse:
    return ThreatActorAssociationResponse.model_validate(asdict(dto))


# ── Global ThreatActor endpoints ────────────────────────────────────────────


@threat_actors_router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=ThreatActorDetailResponse,
    summary="Register a global threat actor",
    description=(
        "Platform-admin-only. A ThreatActor is a global reference record "
        "(ADR-M51.1-02) — never tenant-owned, sourced from a named "
        "external feed or evidence, never fabricated."
    ),
)
async def register_threat_actor(
    body: RegisterThreatActorRequest,
    response: Response,
    svc: ThreatActorServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.THREAT_INTEL_ADMIN)),
) -> ThreatActorDetailResponse:
    dto = await svc.register_threat_actor(
        RegisterThreatActorCommand(
            name=body.name,
            origin=body.origin,
            motivations=tuple(body.motivations),
            sophistication=body.sophistication,
            actor_roles=_ADMIN_ROLES,
        )
    )
    response.headers["Location"] = f"/api/v1/threat-actors/{dto.threat_actor_id}"
    return _detail_response(dto)


@threat_actors_router.get(
    "/{threat_actor_id}",
    response_model=ThreatActorDetailResponse,
    summary="Get a threat actor",
)
async def get_threat_actor(
    threat_actor_id: str,
    svc: ThreatActorServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.THREAT_INTEL_READ)),
) -> ThreatActorDetailResponse:
    dto = await svc.get_threat_actor(
        GetThreatActorQuery(threat_actor_id=threat_actor_id, actor_roles=_VIEWER_ROLES)
    )
    return _detail_response(dto)


@threat_actors_router.get(
    "",
    response_model=ListThreatActorsResponse,
    summary="List threat actors",
)
async def list_threat_actors(
    svc: ThreatActorServiceDep,
    origin: str | None = Query(default=None),
    actor_status: str | None = Query(default=None, alias="status"),
    _tenant: TenantContext = Depends(require_permission(Permission.THREAT_INTEL_READ)),
) -> ListThreatActorsResponse:
    items = await svc.list_threat_actors(
        ListThreatActorsQuery(status=actor_status, origin=origin, actor_roles=_VIEWER_ROLES)
    )
    summaries = [ThreatActorSummaryResponse.model_validate(asdict(i)) for i in items]
    return ListThreatActorsResponse(items=summaries, count=len(summaries))


@threat_actors_router.post(
    "/{threat_actor_id}/aliases",
    response_model=ThreatActorDetailResponse,
    summary="Add an alias to a threat actor",
)
async def add_alias(
    threat_actor_id: str,
    body: AddAliasRequest,
    svc: ThreatActorServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.THREAT_INTEL_ADMIN)),
) -> ThreatActorDetailResponse:
    dto = await svc.add_alias(
        AddAliasCommand(threat_actor_id=threat_actor_id, alias=body.alias, actor_roles=_ADMIN_ROLES)
    )
    return _detail_response(dto)


@threat_actors_router.post(
    "/{threat_actor_id}/techniques",
    response_model=ThreatActorDetailResponse,
    summary="Associate an ATT&CK technique with a threat actor",
)
async def associate_technique(
    threat_actor_id: str,
    body: AssociateTechniqueRequest,
    svc: ThreatActorServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.THREAT_INTEL_ADMIN)),
) -> ThreatActorDetailResponse:
    dto = await svc.associate_technique(
        AssociateTechniqueCommand(
            threat_actor_id=threat_actor_id,
            technique_id=body.technique_id,
            actor_roles=_ADMIN_ROLES,
        )
    )
    return _detail_response(dto)


@threat_actors_router.post(
    "/{threat_actor_id}/indicators",
    response_model=ThreatActorDetailResponse,
    summary="Associate a fused indicator with a threat actor",
)
async def associate_indicator(
    threat_actor_id: str,
    body: AssociateIndicatorRequest,
    svc: ThreatActorServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.THREAT_INTEL_ADMIN)),
) -> ThreatActorDetailResponse:
    dto = await svc.associate_indicator(
        AssociateIndicatorCommand(
            threat_actor_id=threat_actor_id,
            indicator_id=body.indicator_id,
            actor_roles=_ADMIN_ROLES,
        )
    )
    return _detail_response(dto)


@threat_actors_router.patch(
    "/{threat_actor_id}/motivation",
    response_model=ThreatActorDetailResponse,
    summary="Update a threat actor's motivations",
)
async def update_motivation(
    threat_actor_id: str,
    body: UpdateMotivationRequest,
    svc: ThreatActorServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.THREAT_INTEL_ADMIN)),
) -> ThreatActorDetailResponse:
    dto = await svc.update_motivations(
        UpdateMotivationsCommand(
            threat_actor_id=threat_actor_id,
            motivations=tuple(body.motivations),
            actor_roles=_ADMIN_ROLES,
        )
    )
    return _detail_response(dto)


@threat_actors_router.patch(
    "/{threat_actor_id}/sophistication",
    response_model=ThreatActorDetailResponse,
    summary="Update a threat actor's sophistication level",
)
async def update_sophistication(
    threat_actor_id: str,
    body: UpdateSophisticationRequest,
    svc: ThreatActorServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.THREAT_INTEL_ADMIN)),
) -> ThreatActorDetailResponse:
    dto = await svc.update_sophistication(
        UpdateSophisticationCommand(
            threat_actor_id=threat_actor_id,
            sophistication=body.sophistication,
            actor_roles=_ADMIN_ROLES,
        )
    )
    return _detail_response(dto)


@threat_actors_router.patch(
    "/{threat_actor_id}/status",
    response_model=ThreatActorDetailResponse,
    summary="Transition a threat actor's activity status",
)
async def transition_status(
    threat_actor_id: str,
    body: TransitionStatusRequest,
    svc: ThreatActorServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.THREAT_INTEL_ADMIN)),
) -> ThreatActorDetailResponse:
    dto = await svc.transition_activity_status(
        TransitionActivityStatusCommand(
            threat_actor_id=threat_actor_id,
            target_status=body.target_status,
            actor_roles=_ADMIN_ROLES,
        )
    )
    return _detail_response(dto)


# ── Tenant association endpoints ────────────────────────────────────────────


@threat_actors_router.get(
    "/{threat_actor_id}/associations",
    response_model=ListThreatActorAssociationsResponse,
    summary="List this tenant's associations with a threat actor",
)
async def list_associations(
    threat_actor_id: str,
    tenant_id: TenantIdDep,
    svc: ThreatActorServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.THREAT_INTEL_READ)),
) -> ListThreatActorAssociationsResponse:
    items = await svc.list_associations_for_tenant(
        ListAssociationsForTenantQuery(
            tenant_id=tenant_id, threat_actor_id=threat_actor_id, actor_roles=_VIEWER_ROLES
        )
    )
    responses = [_association_response(i) for i in items]
    return ListThreatActorAssociationsResponse(items=responses, count=len(responses))


@threat_actors_router.post(
    "/{threat_actor_id}/associations",
    status_code=status.HTTP_201_CREATED,
    response_model=ThreatActorAssociationResponse,
    summary="Create a tenant-scoped association citing evidence for a threat actor",
    description=(
        "Requires a resolvable evidence citation (ADR-M51.1-08) — rejected, "
        "fail-closed, if the cited entity cannot be validated for this "
        "tenant. Rejects a duplicate active association for the same "
        "(tenant, actor, referenced entity) tuple."
    ),
)
async def create_association(
    threat_actor_id: str,
    body: CreateAssociationRequest,
    response: Response,
    tenant_id: TenantIdDep,
    svc: ThreatActorServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.THREAT_INTEL_ASSOCIATE)),
) -> ThreatActorAssociationResponse:
    dto = await svc.create_association(
        CreateThreatActorAssociationCommand(
            tenant_id=tenant_id,
            threat_actor_id=threat_actor_id,
            referenced_entity_type=body.referenced_entity_type,
            referenced_entity_id=body.referenced_entity_id,
            evidence_citation=body.evidence_citation,
            actor_roles=_ANALYST_ROLES,
        )
    )
    response.headers["Location"] = (
        f"/api/v1/threat-actors/{threat_actor_id}/associations/{dto.association_id}"
    )
    return _association_response(dto)


@threat_actors_router.delete(
    "/{threat_actor_id}/associations/{association_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Retract a tenant-scoped threat-actor association",
    description=(
        "Append-only correction (ADR-M51.1-03): retraction never deletes "
        "the association row, only transitions it to RETRACTED. Retracting "
        "an already-retracted association is rejected."
    ),
)
async def retract_association(
    threat_actor_id: str,
    association_id: str,
    tenant_id: TenantIdDep,
    svc: ThreatActorServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.THREAT_INTEL_ASSOCIATE)),
) -> None:
    # threat_actor_id is part of the URL for REST shape; the service
    # actually scopes retraction by association_id + tenant_id.
    del threat_actor_id
    await svc.retract_association(
        RetractThreatActorAssociationCommand(
            tenant_id=tenant_id, association_id=association_id, actor_roles=_ANALYST_ROLES
        )
    )
