"""Detection pack / exception / evidence / coverage API routers."""

from __future__ import annotations

import base64
from dataclasses import asdict
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response, status

from detection.api.dependencies import (
    CorrelationCoordinatorDep,
    Phase4ServiceDep,
    TenantIdDep,
)
from detection.api.schemas.phase4_schemas import (
    ApproveExceptionRequest,
    CorrelateFindingRequest,
    CorrelateFindingResponse,
    CreatePackRequest,
    DetectionCoverageResponse,
    DetectionEvidenceResponse,
    DetectionExceptionResponse,
    DetectionPackResponse,
    ListExceptionsResponse,
    ListPacksResponse,
    RejectExceptionRequest,
    RenewExceptionRequest,
    RequestExceptionRequest,
    RevokeExceptionRequest,
    SubmitEvidenceRequest,
    SubscribePackRequest,
)
from detection.application.commands.phase4_commands import (
    ApproveDetectionException,
    ComputeDetectionCoverage,
    CreateDetectionPack,
    PublishDetectionPack,
    RejectDetectionException,
    RenewDetectionException,
    RequestDetectionException,
    RevokeDetectionException,
    SubmitEvidence,
    SubscribePackToTenant,
    VerifyEvidenceIntegrity,
)
from redforge.api.security import TenantContext, require_permission
from redforge.domain.identity.value_objects import Permission

packs_router = APIRouter()
exceptions_router = APIRouter()
evidence_router = APIRouter()
coverage_router = APIRouter()


@packs_router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=DetectionPackResponse,
)
async def create_pack(
    body: CreatePackRequest,
    response: Response,
    tenant_id: TenantIdDep,
    svc: Phase4ServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
) -> DetectionPackResponse:
    dto = await svc.create_detection_pack(
        CreateDetectionPack(
            tenant_id=tenant_id,
            pack_key=body.pack_key,
            title=body.title,
            category=body.category,
            maintainer=body.maintainer,
            rule_ids=body.rule_ids,
            description=body.description,
            compliance_framework_id=body.compliance_framework_id,
            tags=body.tags,
        )
    )
    response.headers["Location"] = f"/api/v1/detection-packs/{dto.pack_id}"
    return DetectionPackResponse.model_validate(asdict(dto))


@packs_router.get("", response_model=ListPacksResponse)
async def list_packs(
    tenant_id: TenantIdDep,
    svc: Phase4ServiceDep,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    _tenant: TenantContext = Depends(require_permission(Permission.FINDINGS_READ)),
) -> ListPacksResponse:
    page = await svc.list_packs(tenant_id, limit=limit, offset=offset)
    return ListPacksResponse.model_validate(asdict(page))


@packs_router.post("/{pack_id}/publish", response_model=DetectionPackResponse)
async def publish_pack(
    pack_id: UUID,
    tenant_id: TenantIdDep,
    svc: Phase4ServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
) -> DetectionPackResponse:
    dto = await svc.publish_detection_pack(
        PublishDetectionPack(tenant_id=tenant_id, pack_id=pack_id)
    )
    return DetectionPackResponse.model_validate(asdict(dto))


@packs_router.post("/{pack_id}/subscribe", response_model=DetectionPackResponse)
async def subscribe_pack(
    pack_id: UUID,
    body: SubscribePackRequest,
    tenant_id: TenantIdDep,
    svc: Phase4ServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
) -> DetectionPackResponse:
    dto = await svc.subscribe_pack_to_tenant(
        SubscribePackToTenant(
            tenant_id=tenant_id,
            pack_id=pack_id,
            subscriber_tenant_id=body.subscriber_tenant_id,
        )
    )
    return DetectionPackResponse.model_validate(asdict(dto))


@exceptions_router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=DetectionExceptionResponse,
)
async def request_exception(
    body: RequestExceptionRequest,
    response: Response,
    tenant_id: TenantIdDep,
    svc: Phase4ServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
) -> DetectionExceptionResponse:
    dto = await svc.request_detection_exception(
        RequestDetectionException(
            tenant_id=tenant_id,
            exception_type=body.exception_type,
            scope_kind=body.scope_kind,
            justification=body.justification,
            requester=body.requester,
            valid_until=body.valid_until,
            affected_rule_ids=body.affected_rule_ids,
            finding_id=body.finding_id,
            rule_id=body.rule_id,
            classification=body.classification,
            compliance_mapped=body.compliance_mapped,
            compliance_impact_acknowledged=body.compliance_impact_acknowledged,
            asset_ids=body.asset_ids,
        )
    )
    response.headers["Location"] = f"/api/v1/detection-exceptions/{dto.exception_id}"
    return DetectionExceptionResponse.model_validate(asdict(dto))


@exceptions_router.get("", response_model=ListExceptionsResponse)
async def list_exceptions(
    tenant_id: TenantIdDep,
    svc: Phase4ServiceDep,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    _tenant: TenantContext = Depends(require_permission(Permission.FINDINGS_READ)),
) -> ListExceptionsResponse:
    page = await svc.list_exceptions(tenant_id, limit=limit, offset=offset)
    return ListExceptionsResponse.model_validate(asdict(page))


@exceptions_router.post(
    "/{exception_id}/approve", response_model=DetectionExceptionResponse
)
async def approve_exception(
    exception_id: UUID,
    body: ApproveExceptionRequest,
    tenant_id: TenantIdDep,
    svc: Phase4ServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
) -> DetectionExceptionResponse:
    dto = await svc.approve_detection_exception(
        ApproveDetectionException(
            tenant_id=tenant_id,
            exception_id=exception_id,
            approver=body.approver,
        )
    )
    return DetectionExceptionResponse.model_validate(asdict(dto))


@exceptions_router.post(
    "/{exception_id}/reject", response_model=DetectionExceptionResponse
)
async def reject_exception(
    exception_id: UUID,
    body: RejectExceptionRequest,
    tenant_id: TenantIdDep,
    svc: Phase4ServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
) -> DetectionExceptionResponse:
    dto = await svc.reject_detection_exception(
        RejectDetectionException(
            tenant_id=tenant_id,
            exception_id=exception_id,
            rejector=body.rejector,
            reason=body.reason,
        )
    )
    return DetectionExceptionResponse.model_validate(asdict(dto))


@exceptions_router.post(
    "/{exception_id}/renew", response_model=DetectionExceptionResponse
)
async def renew_exception(
    exception_id: UUID,
    body: RenewExceptionRequest,
    tenant_id: TenantIdDep,
    svc: Phase4ServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
) -> DetectionExceptionResponse:
    dto = await svc.renew_detection_exception(
        RenewDetectionException(
            tenant_id=tenant_id,
            exception_id=exception_id,
            renewer=body.renewer,
            new_valid_until=body.new_valid_until,
        )
    )
    return DetectionExceptionResponse.model_validate(asdict(dto))


@exceptions_router.post(
    "/{exception_id}/revoke", response_model=DetectionExceptionResponse
)
async def revoke_exception(
    exception_id: UUID,
    body: RevokeExceptionRequest,
    tenant_id: TenantIdDep,
    svc: Phase4ServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
) -> DetectionExceptionResponse:
    dto = await svc.revoke_detection_exception(
        RevokeDetectionException(
            tenant_id=tenant_id,
            exception_id=exception_id,
            revoker=body.revoker,
            reason=body.reason,
        )
    )
    return DetectionExceptionResponse.model_validate(asdict(dto))


@evidence_router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=DetectionEvidenceResponse,
)
async def submit_evidence(
    body: SubmitEvidenceRequest,
    response: Response,
    tenant_id: TenantIdDep,
    svc: Phase4ServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
) -> DetectionEvidenceResponse:
    payload = base64.b64decode(body.payload_b64)
    dto = await svc.submit_evidence(
        SubmitEvidence(
            tenant_id=tenant_id,
            evidence_type=body.evidence_type,
            payload=payload,
            collected_by=body.collected_by,
            finding_id=body.finding_id,
            exception_id=body.exception_id,
            simulation_id=body.simulation_id,
            storage_uri=body.storage_uri,
        )
    )
    response.headers["Location"] = f"/api/v1/detection-evidence/{dto.evidence_id}"
    return DetectionEvidenceResponse.model_validate(asdict(dto))


@evidence_router.post(
    "/{evidence_id}/verify", response_model=DetectionEvidenceResponse
)
async def verify_evidence(
    evidence_id: UUID,
    tenant_id: TenantIdDep,
    svc: Phase4ServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
) -> DetectionEvidenceResponse:
    dto = await svc.verify_evidence_integrity(
        VerifyEvidenceIntegrity(tenant_id=tenant_id, evidence_id=evidence_id)
    )
    return DetectionEvidenceResponse.model_validate(asdict(dto))


@coverage_router.get("", response_model=DetectionCoverageResponse)
async def get_coverage(
    tenant_id: TenantIdDep,
    svc: Phase4ServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.FINDINGS_READ)),
) -> DetectionCoverageResponse:
    dto = await svc.compute_detection_coverage(
        ComputeDetectionCoverage(tenant_id=tenant_id)
    )
    return DetectionCoverageResponse.model_validate(asdict(dto))


async def correlate_finding_endpoint(
    finding_id: UUID,
    body: CorrelateFindingRequest,
    tenant_id: TenantIdDep,
    coordinator: CorrelationCoordinatorDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
) -> CorrelateFindingResponse:
    result = await coordinator.correlate_finding(
        tenant_uuid=tenant_id,
        finding_id=finding_id,
        refresh=body.refresh,
    )
    return CorrelateFindingResponse.model_validate(result)
