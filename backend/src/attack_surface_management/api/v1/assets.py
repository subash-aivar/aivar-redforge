"""Asset CRUD, discovery-query, and exposure/criticality API routers
(M49D).

Endpoint set is bounded strictly by what `AssetApplicationService`/
`AttackSurfaceQueryService` actually expose. No endpoint here invents a
capability the frozen M49B application layer does not already have."""

from __future__ import annotations

from dataclasses import asdict
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from attack_surface_management.api.dependencies import (
    AssetServiceDep,
    QueryServiceDep,
    TenantIdDep,
)
from attack_surface_management.api.schemas.attack_surface_schemas import (
    AddDnsRecordRequest,
    AddTechnologyFingerprintRequest,
    AssetResponse,
    AttachCertificateRequest,
    CriticalityScoreResponse,
    ListAssetsResponse,
    ReclassifyAssetRequest,
    RecordOpenPortRequest,
    RegisterAssetRequest,
    SetCriticalityRequest,
    TransitionAssetLifecycleRequest,
    UpdateOwnershipRequest,
)
from attack_surface_management.application.commands.asset_commands import (
    AddDnsRecordCommand,
    AddTechnologyFingerprintCommand,
    AttachCertificateCommand,
    ClosePortCommand,
    DecommissionAssetCommand,
    EvaluateExposureCommand,
    ReclassifyAssetCommand,
    RecomputeCriticalityScoreCommand,
    RecordOpenPortCommand,
    RegisterAssetCommand,
    RemoveDnsRecordCommand,
    RevokeCertificateCommand,
    SetCriticalityCommand,
    TransitionAssetLifecycleCommand,
    UpdateOwnershipCommand,
)
from attack_surface_management.application.dtos.asset_dto import AssetDTO
from attack_surface_management.application.queries.asset_queries import (
    GetAssetQuery,
    ListAssetsQuery,
)
from attack_surface_management.domain.value_objects.domain_name import DomainName, Subdomain
from attack_surface_management.domain.value_objects.enums import (
    AssetClassification,
    AssetLifecycleState,
    AssetType,
    CertificateStatus,
    Criticality,
    DiscoverySource,
    DnsRecordType,
    ExposureState,
    PortProtocol,
)
from attack_surface_management.domain.value_objects.identifiers import (
    AssetId,
    CertificateId,
    DnsRecordId,
    PortId,
)
from attack_surface_management.domain.value_objects.ip_address import IPAddress
from attack_surface_management.domain.value_objects.service_banner import ServiceBanner
from redforge.api.security import TenantContext, require_permission
from redforge.domain.identity.value_objects import Permission

assets_router = APIRouter()


def _asset_response(dto: AssetDTO) -> AssetResponse:
    return AssetResponse.model_validate(asdict(dto))


def _domain_identifiers(
    body: RegisterAssetRequest,
) -> tuple[DomainName | None, Subdomain | None, IPAddress | None]:
    try:
        domain_name = DomainName(body.domain_name) if body.domain_name else None
        subdomain = (
            Subdomain(body.subdomain, domain_name)
            if body.subdomain and domain_name is not None
            else None
        )
        ip_address = IPAddress(body.ip_address) if body.ip_address else None
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return domain_name, subdomain, ip_address


@assets_router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=AssetResponse,
    summary="Register a discovered asset",
)
async def register_asset(
    body: RegisterAssetRequest,
    response: Response,
    tenant_id: TenantIdDep,
    svc: AssetServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_MANAGE)),
) -> AssetResponse:
    try:
        asset_type = AssetType(body.asset_type)
        discovery_source = DiscoverySource(body.discovery_source) if body.discovery_source else None
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    domain_name, subdomain, ip_address = _domain_identifiers(body)
    dto = await svc.register_asset(
        RegisterAssetCommand(
            tenant_id=tenant_id,
            asset_type=asset_type,
            domain_name=domain_name,
            subdomain=subdomain,
            ip_address=ip_address,
            discovery_source=discovery_source,
            asset_id=AssetId(UUID(body.asset_id)) if body.asset_id else None,
        )
    )
    response.headers["Location"] = f"/api/v1/attack-surface-management/assets/{dto.asset_id}"
    return _asset_response(dto)


@assets_router.get(
    "/{asset_id}",
    response_model=AssetResponse,
    summary="Get an asset",
)
async def get_asset(
    asset_id: UUID,
    tenant_id: TenantIdDep,
    svc: QueryServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_READ)),
) -> AssetResponse:
    dto = await svc.get_asset(GetAssetQuery(tenant_id=tenant_id, asset_id=AssetId(asset_id)))
    if dto is None:
        raise HTTPException(status_code=404, detail=f"No asset {asset_id}")
    return _asset_response(dto)


@assets_router.get(
    "",
    response_model=ListAssetsResponse,
    summary="List assets",
)
async def list_assets(
    tenant_id: TenantIdDep,
    svc: QueryServiceDep,
    asset_type: AssetType | None = Query(default=None),
    classification: AssetClassification | None = Query(default=None),
    criticality: Criticality | None = Query(default=None),
    exposure_state: ExposureState | None = Query(default=None),
    lifecycle_state: AssetLifecycleState | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_READ)),
) -> ListAssetsResponse:
    items = await svc.list_assets(
        ListAssetsQuery(
            tenant_id=tenant_id,
            asset_type=asset_type,
            classification=classification,
            criticality=criticality,
            exposure_state=exposure_state,
            lifecycle_state=lifecycle_state,
            limit=limit,
            offset=offset,
        )
    )
    return ListAssetsResponse(items=[_asset_response(i) for i in items], count=len(items))


@assets_router.post(
    "/{asset_id}/ports",
    response_model=AssetResponse,
    summary="Record a discovered open port on an asset",
)
async def record_open_port(
    asset_id: UUID,
    body: RecordOpenPortRequest,
    tenant_id: TenantIdDep,
    svc: AssetServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_MANAGE)),
) -> AssetResponse:
    try:
        protocol = PortProtocol(body.protocol)
        service = (
            ServiceBanner(
                name=body.service.name, version=body.service.version, banner=body.service.banner
            )
            if body.service is not None
            else None
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    dto = await svc.record_open_port(
        RecordOpenPortCommand(
            tenant_id=tenant_id,
            asset_id=AssetId(asset_id),
            port_number=body.port_number,
            protocol=protocol,
            service=service,
            port_id=PortId(UUID(body.port_id)) if body.port_id else None,
        )
    )
    return _asset_response(dto)


@assets_router.post(
    "/{asset_id}/ports/{port_id}/close",
    response_model=AssetResponse,
    summary="Close an open port on an asset",
)
async def close_port(
    asset_id: UUID,
    port_id: UUID,
    tenant_id: TenantIdDep,
    svc: AssetServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_MANAGE)),
) -> AssetResponse:
    dto = await svc.close_port(
        ClosePortCommand(tenant_id=tenant_id, asset_id=AssetId(asset_id), port_id=PortId(port_id))
    )
    return _asset_response(dto)


@assets_router.post(
    "/{asset_id}/certificates",
    response_model=AssetResponse,
    summary="Attach a certificate to an asset",
)
async def attach_certificate(
    asset_id: UUID,
    body: AttachCertificateRequest,
    tenant_id: TenantIdDep,
    svc: AssetServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_MANAGE)),
) -> AssetResponse:
    try:
        certificate_status = CertificateStatus(body.status)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    dto = await svc.attach_certificate(
        AttachCertificateCommand(
            tenant_id=tenant_id,
            asset_id=AssetId(asset_id),
            common_name=body.common_name,
            issuer=body.issuer,
            serial_number=body.serial_number,
            not_before=body.not_before,
            not_after=body.not_after,
            status=certificate_status,
            certificate_id=(
                CertificateId(UUID(body.certificate_id)) if body.certificate_id else None
            ),
        )
    )
    return _asset_response(dto)


@assets_router.post(
    "/{asset_id}/certificates/{certificate_id}/revoke",
    response_model=AssetResponse,
    summary="Revoke a certificate attached to an asset",
)
async def revoke_certificate(
    asset_id: UUID,
    certificate_id: UUID,
    tenant_id: TenantIdDep,
    svc: AssetServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_MANAGE)),
) -> AssetResponse:
    dto = await svc.revoke_certificate(
        RevokeCertificateCommand(
            tenant_id=tenant_id,
            asset_id=AssetId(asset_id),
            certificate_id=CertificateId(certificate_id),
        )
    )
    return _asset_response(dto)


@assets_router.post(
    "/{asset_id}/dns-records",
    response_model=AssetResponse,
    summary="Add a DNS record observed for an asset",
)
async def add_dns_record(
    asset_id: UUID,
    body: AddDnsRecordRequest,
    tenant_id: TenantIdDep,
    svc: AssetServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_MANAGE)),
) -> AssetResponse:
    try:
        record_type = DnsRecordType(body.record_type)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    dto = await svc.add_dns_record(
        AddDnsRecordCommand(
            tenant_id=tenant_id,
            asset_id=AssetId(asset_id),
            record_type=record_type,
            name=body.name,
            value=body.value,
            ttl_seconds=body.ttl_seconds,
            record_id=DnsRecordId(UUID(body.record_id)) if body.record_id else None,
        )
    )
    return _asset_response(dto)


@assets_router.post(
    "/{asset_id}/dns-records/{record_id}/remove",
    response_model=AssetResponse,
    summary="Remove a DNS record from an asset",
)
async def remove_dns_record(
    asset_id: UUID,
    record_id: UUID,
    tenant_id: TenantIdDep,
    svc: AssetServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_MANAGE)),
) -> AssetResponse:
    dto = await svc.remove_dns_record(
        RemoveDnsRecordCommand(
            tenant_id=tenant_id, asset_id=AssetId(asset_id), record_id=DnsRecordId(record_id)
        )
    )
    return _asset_response(dto)


@assets_router.post(
    "/{asset_id}/fingerprints",
    response_model=AssetResponse,
    summary="Add a technology fingerprint detected on an asset",
)
async def add_technology_fingerprint(
    asset_id: UUID,
    body: AddTechnologyFingerprintRequest,
    tenant_id: TenantIdDep,
    svc: AssetServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_MANAGE)),
) -> AssetResponse:
    dto = await svc.add_technology_fingerprint(
        AddTechnologyFingerprintCommand(
            tenant_id=tenant_id,
            asset_id=AssetId(asset_id),
            name=body.name,
            version=body.version,
            confidence=body.confidence,
        )
    )
    return _asset_response(dto)


@assets_router.post(
    "/{asset_id}/evaluate-exposure",
    response_model=AssetResponse,
    summary="Recompute and apply an asset's observed exposure state",
)
async def evaluate_exposure(
    asset_id: UUID,
    tenant_id: TenantIdDep,
    svc: AssetServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_MANAGE)),
) -> AssetResponse:
    dto = await svc.evaluate_exposure(
        EvaluateExposureCommand(tenant_id=tenant_id, asset_id=AssetId(asset_id))
    )
    return _asset_response(dto)


@assets_router.get(
    "/{asset_id}/criticality-score",
    response_model=CriticalityScoreResponse,
    summary="Compute an asset's derived criticality score",
)
async def recompute_criticality_score(
    asset_id: UUID,
    tenant_id: TenantIdDep,
    svc: AssetServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_READ)),
) -> CriticalityScoreResponse:
    dto = await svc.recompute_criticality_score(
        RecomputeCriticalityScoreCommand(tenant_id=tenant_id, asset_id=AssetId(asset_id))
    )
    return CriticalityScoreResponse.model_validate(asdict(dto))


@assets_router.post(
    "/{asset_id}/criticality",
    response_model=AssetResponse,
    summary="Set an asset's business-assigned criticality tier",
)
async def set_criticality(
    asset_id: UUID,
    body: SetCriticalityRequest,
    tenant_id: TenantIdDep,
    svc: AssetServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_MANAGE)),
) -> AssetResponse:
    try:
        criticality = Criticality(body.criticality)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    dto = await svc.set_criticality(
        SetCriticalityCommand(
            tenant_id=tenant_id, asset_id=AssetId(asset_id), criticality=criticality
        )
    )
    return _asset_response(dto)


@assets_router.post(
    "/{asset_id}/reclassify",
    response_model=AssetResponse,
    summary="Reclassify an asset's business/environment tag",
)
async def reclassify_asset(
    asset_id: UUID,
    body: ReclassifyAssetRequest,
    tenant_id: TenantIdDep,
    svc: AssetServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_MANAGE)),
) -> AssetResponse:
    try:
        classification = AssetClassification(body.classification)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    dto = await svc.reclassify(
        ReclassifyAssetCommand(
            tenant_id=tenant_id, asset_id=AssetId(asset_id), classification=classification
        )
    )
    return _asset_response(dto)


@assets_router.post(
    "/{asset_id}/ownership",
    response_model=AssetResponse,
    summary="Assign/update an asset's ownership",
)
async def update_ownership(
    asset_id: UUID,
    body: UpdateOwnershipRequest,
    tenant_id: TenantIdDep,
    svc: AssetServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_MANAGE)),
) -> AssetResponse:
    dto = await svc.update_ownership(
        UpdateOwnershipCommand(
            tenant_id=tenant_id,
            asset_id=AssetId(asset_id),
            owning_team=body.owning_team,
            contact=body.contact,
        )
    )
    return _asset_response(dto)


@assets_router.post(
    "/{asset_id}/lifecycle",
    response_model=AssetResponse,
    summary="Transition an asset's lifecycle state",
)
async def transition_lifecycle(
    asset_id: UUID,
    body: TransitionAssetLifecycleRequest,
    tenant_id: TenantIdDep,
    svc: AssetServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_MANAGE)),
) -> AssetResponse:
    try:
        new_state = AssetLifecycleState(body.new_state)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    dto = await svc.transition_lifecycle(
        TransitionAssetLifecycleCommand(
            tenant_id=tenant_id, asset_id=AssetId(asset_id), new_state=new_state
        )
    )
    return _asset_response(dto)


@assets_router.post(
    "/{asset_id}/decommission",
    response_model=AssetResponse,
    summary="Decommission an asset",
)
async def decommission_asset(
    asset_id: UUID,
    tenant_id: TenantIdDep,
    svc: AssetServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ANALYTICS_MANAGE)),
) -> AssetResponse:
    dto = await svc.decommission(
        DecommissionAssetCommand(tenant_id=tenant_id, asset_id=AssetId(asset_id))
    )
    return _asset_response(dto)
