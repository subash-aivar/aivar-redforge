"""Payload and plugin API routes."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response, status

from payload.api.dependencies import PayloadServiceDep, PrincipalIdDep, TenantIdDep
from payload.api.schemas.payload_schemas import (
    ApprovePayloadRequest,
    ApprovePluginRequest,
    DeprecatePayloadRequest,
    HashVerificationResponse,
    ListPayloadsResponse,
    ListPluginsResponse,
    PayloadResponse,
    PluginResponse,
    PublishPayloadVersionRequest,
    RegisterPayloadRequest,
    RegisterPluginRequest,
    RevokePayloadRequest,
    VerifyPayloadHashRequest,
)
from payload.application.commands.payload_commands import (
    ApprovePayload,
    ApprovePlugin,
    DeprecatePayload,
    PublishPayloadVersion,
    RegisterPayload,
    RegisterPlugin,
    RevokePayload,
    VerifyPayloadHash,
)
from payload.application.queries.payload_queries import (
    GetPayload,
    GetPlugin,
    ListPayloads,
    ListPlugins,
)
from redforge.api.security import TenantContext, require_permission
from redforge.domain.identity.value_objects import Permission

payloads_router = APIRouter()
plugins_router = APIRouter()


@payloads_router.post(
    "/",
    status_code=status.HTTP_201_CREATED,
    response_model=PayloadResponse,
)
async def register_payload(
    body: RegisterPayloadRequest,
    response: Response,
    tenant_id: TenantIdDep,
    svc: PayloadServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ADMIN)),
) -> PayloadResponse:
    dto = await svc.register_payload(
        RegisterPayload(
            tenant_id=tenant_id,
            payload_key=body.payload_key,
            payload_type=body.payload_type,
            impact_ceiling=body.impact_ceiling,
            engagement_classes=tuple(body.engagement_classes),
        )
    )
    response.headers["Location"] = f"/api/v1/red-team-payloads/{dto.payload_id}"
    return PayloadResponse.from_dto(dto)


@payloads_router.get("/", response_model=ListPayloadsResponse)
async def list_payloads(
    tenant_id: TenantIdDep,
    svc: PayloadServiceDep,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_AUDITOR)),
) -> ListPayloadsResponse:
    items = await svc.list_payloads(
        ListPayloads(tenant_id=tenant_id, limit=limit, offset=offset)
    )
    return ListPayloadsResponse(items=[PayloadResponse.from_dto(i) for i in items])


@payloads_router.get("/{payload_id}", response_model=PayloadResponse)
async def get_payload(
    payload_id: UUID,
    tenant_id: TenantIdDep,
    svc: PayloadServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_AUDITOR)),
) -> PayloadResponse:
    dto = await svc.get_payload(
        GetPayload(tenant_id=tenant_id, payload_id=payload_id)
    )
    return PayloadResponse.from_dto(dto)


@payloads_router.post(
    "/{payload_id}/versions",
    response_model=PayloadResponse,
)
async def publish_version(
    payload_id: UUID,
    body: PublishPayloadVersionRequest,
    tenant_id: TenantIdDep,
    svc: PayloadServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ADMIN)),
) -> PayloadResponse:
    dto = await svc.publish_payload_version(
        PublishPayloadVersion(
            tenant_id=tenant_id,
            payload_id=payload_id,
            version=body.version,
            payload_hash=body.payload_hash,
            storage_ref=body.storage_ref,
            technique_ids=tuple(body.technique_ids),
            vulnerability_refs=tuple(body.vulnerability_refs),
        )
    )
    return PayloadResponse.from_dto(dto)


@payloads_router.post(
    "/{payload_id}/approve",
    response_model=PayloadResponse,
)
async def approve_payload(
    payload_id: UUID,
    body: ApprovePayloadRequest,
    tenant_id: TenantIdDep,
    svc: PayloadServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_APPROVER)),
) -> PayloadResponse:
    dto = await svc.approve_payload(
        ApprovePayload(
            tenant_id=tenant_id,
            payload_id=payload_id,
            approved_by=body.approved_by,
            signature=body.signature,
            ciso_approved=body.ciso_approved,
            engagement_classes=(
                tuple(body.engagement_classes)
                if body.engagement_classes is not None
                else None
            ),
        )
    )
    return PayloadResponse.from_dto(dto)


@payloads_router.post(
    "/{payload_id}/deprecate",
    response_model=PayloadResponse,
)
async def deprecate_payload(
    payload_id: UUID,
    body: DeprecatePayloadRequest,
    tenant_id: TenantIdDep,
    svc: PayloadServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ADMIN)),
) -> PayloadResponse:
    dto = await svc.deprecate_payload(
        DeprecatePayload(
            tenant_id=tenant_id,
            payload_id=payload_id,
            reason=body.reason,
        )
    )
    return PayloadResponse.from_dto(dto)


@payloads_router.post(
    "/{payload_id}/revoke",
    response_model=PayloadResponse,
)
async def revoke_payload(
    payload_id: UUID,
    body: RevokePayloadRequest,
    tenant_id: TenantIdDep,
    svc: PayloadServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ADMIN)),
) -> PayloadResponse:
    dto = await svc.revoke_payload(
        RevokePayload(
            tenant_id=tenant_id,
            payload_id=payload_id,
            reason=body.reason,
            revoked_by=body.revoked_by,
        )
    )
    return PayloadResponse.from_dto(dto)


@payloads_router.post(
    "/{payload_id}/verify-hash",
    response_model=HashVerificationResponse,
)
async def verify_payload_hash(
    payload_id: UUID,
    body: VerifyPayloadHashRequest,
    tenant_id: TenantIdDep,
    svc: PayloadServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_OPERATOR)),
) -> HashVerificationResponse:
    dto = await svc.verify_payload_hash(
        VerifyPayloadHash(
            tenant_id=tenant_id,
            payload_id=payload_id,
            computed_hash=body.computed_hash,
        )
    )
    return HashVerificationResponse.from_dto(dto)


@plugins_router.post(
    "/",
    status_code=status.HTTP_201_CREATED,
    response_model=PluginResponse,
)
async def register_plugin(
    body: RegisterPluginRequest,
    response: Response,
    tenant_id: TenantIdDep,
    svc: PayloadServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ADMIN)),
) -> PluginResponse:
    dto = await svc.register_plugin(
        RegisterPlugin(
            tenant_id=tenant_id,
            name=body.name,
            plugin_type=body.plugin_type,
            plugin_version=body.plugin_version,
            plugin_hash=body.plugin_hash,
            technique_ids=tuple(body.technique_ids),
            trust_level=body.trust_level,
        )
    )
    response.headers["Location"] = (
        f"/api/v1/red-team-payloads/plugins/{dto.plugin_id}"
    )
    return PluginResponse.from_dto(dto)


@plugins_router.get("/", response_model=ListPluginsResponse)
async def list_plugins(
    tenant_id: TenantIdDep,
    svc: PayloadServiceDep,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_AUDITOR)),
) -> ListPluginsResponse:
    items = await svc.list_plugins(
        ListPlugins(tenant_id=tenant_id, limit=limit, offset=offset)
    )
    return ListPluginsResponse(items=[PluginResponse.from_dto(i) for i in items])


@plugins_router.get("/{plugin_id}", response_model=PluginResponse)
async def get_plugin(
    plugin_id: UUID,
    tenant_id: TenantIdDep,
    svc: PayloadServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_AUDITOR)),
) -> PluginResponse:
    dto = await svc.get_plugin(GetPlugin(tenant_id=tenant_id, plugin_id=plugin_id))
    return PluginResponse.from_dto(dto)


@plugins_router.post(
    "/{plugin_id}/approve",
    response_model=PluginResponse,
)
async def approve_plugin(
    plugin_id: UUID,
    body: ApprovePluginRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: PayloadServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_APPROVER)),
) -> PluginResponse:
    _ = principal_id
    dto = await svc.approve_plugin(
        ApprovePlugin(
            tenant_id=tenant_id,
            plugin_id=plugin_id,
            approved_by=body.approved_by,
        )
    )
    return PluginResponse.from_dto(dto)
