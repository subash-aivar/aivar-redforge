"""Evidence API routes — collect, verify, custody, chain lifecycle."""

from __future__ import annotations

import base64
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response, status

from evidence.api.dependencies import EvidenceServiceDep, PrincipalIdDep, TenantIdDep
from evidence.api.schemas.evidence_schemas import (
    AddEvidenceToChainRequest,
    ChainIntegrityReportResponse,
    CollectEvidenceRequest,
    EvidenceChainResponse,
    ExecutionEvidenceResponse,
    IntegrityVerificationResponse,
    ListEvidenceChainsResponse,
    ListEvidenceResponse,
    OpenEvidenceChainRequest,
    SealEvidenceChainRequest,
    SubmitEvidenceChainRequest,
    TransferCustodyRequest,
)
from evidence.application.commands.evidence_commands import (
    AddEvidenceToChain,
    CollectEvidence,
    OpenEvidenceChain,
    QueryEvidenceChainIntegrity,
    RequestEvidenceDeletion,
    SealEvidenceChain,
    SubmitEvidenceChain,
    TransferCustody,
    VerifyEvidenceIntegrity,
)
from evidence.application.queries.evidence_queries import (
    GetEvidence,
    GetEvidenceChain,
    GetEvidenceChainByOperation,
    ListEvidenceByOperation,
)
from evidence.domain.value_objects.enums import EVIDENCE_SEALER_ROLE
from redforge.api.security import TenantContext, require_permission
from redforge.domain.identity.value_objects import Permission

evidence_router = APIRouter()
chains_router = APIRouter()


@evidence_router.post(
    "/",
    status_code=status.HTTP_201_CREATED,
    response_model=ExecutionEvidenceResponse,
)
async def collect_evidence(
    body: CollectEvidenceRequest,
    response: Response,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: EvidenceServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_OPERATOR)),
) -> ExecutionEvidenceResponse:
    _ = principal_id
    payload = base64.b64decode(body.payload_b64)
    dto = await svc.collect_evidence(
        CollectEvidence(
            tenant_id=tenant_id,
            action_id=body.action_id,
            engagement_id=body.engagement_id,
            operation_id=body.operation_id,
            evidence_type=body.evidence_type,
            payload=payload,
            collected_by=body.collected_by,
            retention_class=body.retention_class,
            corrects_evidence_id=body.corrects_evidence_id,
        )
    )
    response.headers["Location"] = f"/api/v1/red-team-evidence/{dto.evidence_id}"
    return ExecutionEvidenceResponse.from_dto(dto)


@evidence_router.get(
    "/by-operation/{operation_id}",
    response_model=ListEvidenceResponse,
)
async def list_evidence_by_operation(
    operation_id: UUID,
    tenant_id: TenantIdDep,
    svc: EvidenceServiceDep,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_AUDITOR)),
) -> ListEvidenceResponse:
    items = await svc.list_evidence_by_operation(
        ListEvidenceByOperation(
            tenant_id=tenant_id,
            operation_id=operation_id,
            limit=limit,
            offset=offset,
        )
    )
    return ListEvidenceResponse(
        items=[ExecutionEvidenceResponse.from_dto(i) for i in items]
    )


@evidence_router.get("/{evidence_id}", response_model=ExecutionEvidenceResponse)
async def get_evidence(
    evidence_id: UUID,
    tenant_id: TenantIdDep,
    svc: EvidenceServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_AUDITOR)),
) -> ExecutionEvidenceResponse:
    dto = await svc.get_evidence(
        GetEvidence(tenant_id=tenant_id, evidence_id=evidence_id)
    )
    return ExecutionEvidenceResponse.from_dto(dto)


@evidence_router.post(
    "/{evidence_id}/verify",
    response_model=IntegrityVerificationResponse,
)
async def verify_evidence(
    evidence_id: UUID,
    tenant_id: TenantIdDep,
    svc: EvidenceServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_AUDITOR)),
) -> IntegrityVerificationResponse:
    dto = await svc.verify_evidence_integrity(
        VerifyEvidenceIntegrity(tenant_id=tenant_id, evidence_id=evidence_id)
    )
    return IntegrityVerificationResponse.from_dto(dto)


@evidence_router.post(
    "/{evidence_id}/transfer-custody",
    response_model=ExecutionEvidenceResponse,
)
async def transfer_custody(
    evidence_id: UUID,
    body: TransferCustodyRequest,
    tenant_id: TenantIdDep,
    svc: EvidenceServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_OPERATOR)),
) -> ExecutionEvidenceResponse:
    dto = await svc.transfer_custody(
        TransferCustody(
            tenant_id=tenant_id,
            evidence_id=evidence_id,
            new_custodian=body.new_custodian,
            custody_action=body.custody_action,
        )
    )
    return ExecutionEvidenceResponse.from_dto(dto)


@evidence_router.post(
    "/{evidence_id}/request-deletion",
    response_model=ExecutionEvidenceResponse,
)
async def request_deletion(
    evidence_id: UUID,
    tenant_id: TenantIdDep,
    svc: EvidenceServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ADMIN)),
) -> ExecutionEvidenceResponse:
    dto = await svc.request_evidence_deletion(
        RequestEvidenceDeletion(tenant_id=tenant_id, evidence_id=evidence_id)
    )
    return ExecutionEvidenceResponse.from_dto(dto)


@chains_router.post(
    "/",
    status_code=status.HTTP_201_CREATED,
    response_model=EvidenceChainResponse,
)
async def open_evidence_chain(
    body: OpenEvidenceChainRequest,
    response: Response,
    tenant_id: TenantIdDep,
    svc: EvidenceServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_OPERATOR)),
) -> EvidenceChainResponse:
    dto = await svc.open_evidence_chain(
        OpenEvidenceChain(
            tenant_id=tenant_id,
            operation_id=body.operation_id,
            engagement_id=body.engagement_id,
        )
    )
    response.headers["Location"] = f"/api/v1/red-team-evidence/chains/{dto.chain_id}"
    return EvidenceChainResponse.from_dto(dto)


@chains_router.get(
    "/by-operation/{operation_id}",
    response_model=ListEvidenceChainsResponse,
)
async def list_chains_by_operation(
    operation_id: UUID,
    tenant_id: TenantIdDep,
    svc: EvidenceServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_AUDITOR)),
) -> ListEvidenceChainsResponse:
    from evidence.application.exceptions import ApplicationNotFoundError

    try:
        dto = await svc.get_evidence_chain_by_operation(
            GetEvidenceChainByOperation(tenant_id=tenant_id, operation_id=operation_id)
        )
    except ApplicationNotFoundError:
        return ListEvidenceChainsResponse(items=[])
    return ListEvidenceChainsResponse(items=[EvidenceChainResponse.from_dto(dto)])


@chains_router.get("/{chain_id}", response_model=EvidenceChainResponse)
async def get_evidence_chain(
    chain_id: UUID,
    tenant_id: TenantIdDep,
    svc: EvidenceServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_AUDITOR)),
) -> EvidenceChainResponse:
    dto = await svc.get_evidence_chain(
        GetEvidenceChain(tenant_id=tenant_id, chain_id=chain_id)
    )
    return EvidenceChainResponse.from_dto(dto)


@chains_router.post(
    "/{chain_id}/entries",
    response_model=EvidenceChainResponse,
)
async def add_evidence_to_chain(
    chain_id: UUID,
    body: AddEvidenceToChainRequest,
    tenant_id: TenantIdDep,
    svc: EvidenceServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_OPERATOR)),
) -> EvidenceChainResponse:
    dto = await svc.add_evidence_to_chain(
        AddEvidenceToChain(
            tenant_id=tenant_id,
            chain_id=chain_id,
            evidence_id=body.evidence_id,
        )
    )
    return EvidenceChainResponse.from_dto(dto)


@chains_router.post(
    "/{chain_id}/seal",
    response_model=EvidenceChainResponse,
)
async def seal_evidence_chain(
    chain_id: UUID,
    body: SealEvidenceChainRequest,
    tenant_id: TenantIdDep,
    svc: EvidenceServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ADMIN)),
) -> EvidenceChainResponse:
    sealer_role = body.sealer_role or EVIDENCE_SEALER_ROLE
    dto = await svc.seal_evidence_chain(
        SealEvidenceChain(
            tenant_id=tenant_id,
            chain_id=chain_id,
            sealer_operator_id=body.sealer_operator_id,
            sealer_role=sealer_role,
            signature=body.signature,
        )
    )
    return EvidenceChainResponse.from_dto(dto)


@chains_router.post(
    "/{chain_id}/submit",
    response_model=EvidenceChainResponse,
)
async def submit_evidence_chain(
    chain_id: UUID,
    body: SubmitEvidenceChainRequest,
    tenant_id: TenantIdDep,
    svc: EvidenceServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_ADMIN)),
) -> EvidenceChainResponse:
    dto = await svc.submit_evidence_chain(
        SubmitEvidenceChain(
            tenant_id=tenant_id,
            chain_id=chain_id,
            destination_ref=body.destination_ref,
        )
    )
    return EvidenceChainResponse.from_dto(dto)


@chains_router.post(
    "/{chain_id}/integrity",
    response_model=ChainIntegrityReportResponse,
)
async def query_chain_integrity(
    chain_id: UUID,
    tenant_id: TenantIdDep,
    svc: EvidenceServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.REDTEAM_AUDITOR)),
) -> ChainIntegrityReportResponse:
    dto = await svc.query_evidence_chain_integrity(
        QueryEvidenceChainIntegrity(tenant_id=tenant_id, chain_id=chain_id)
    )
    return ChainIntegrityReportResponse.from_dto(dto)
