from __future__ import annotations

from dataclasses import asdict
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException

from ai_supply_chain.api.dependencies import get_actor_roles, get_container, get_tenant_id
from ai_supply_chain.api.schemas.supply_chain_schemas import (
    BuildMBOMRequest,
    RecordProvenanceRequest,
    RunDiscoveryScanRequest,
    SetThresholdRequest,
    VerifyProvenanceRequest,
)
from ai_supply_chain.application.commands.supply_chain_commands import (
    BuildMBOMCommand,
    ManualResetVerificationCommand,
    RecordModelProvenanceCommand,
    RunDiscoveryScanCommand,
    SetVerificationThresholdCommand,
    VerifyModelProvenanceCommand,
)
from ai_supply_chain.application.exceptions import (
    ApplicationForbiddenError,
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from ai_supply_chain.infrastructure.container import SupplyChainContainer

router = APIRouter(prefix="/ai-supply-chain", tags=["ai-supply-chain"])


def _map_error(exc: Exception) -> HTTPException:
    if isinstance(exc, ApplicationNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, ApplicationForbiddenError):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, ApplicationValidationError):
        return HTTPException(status_code=400, detail=str(exc))
    return HTTPException(status_code=500, detail=str(exc))


@router.post("/provenances")
async def record_provenance(
    body: RecordProvenanceRequest,
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: SupplyChainContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.provenance_service.record(
            RecordModelProvenanceCommand(
                tenant_id=tenant_id,
                asset_id=body.asset_id,
                model_origin=body.model_origin,
                artifact_size_bytes=body.artifact_size_bytes,
                registry_provider=body.registry_provider,
                registry_id=body.registry_id,
                training_data_description=body.training_data_description,
                actor_roles=roles,
            )
        )
    except Exception as exc:
        raise _map_error(exc) from exc
    return asdict(dto)


@router.post("/provenances/{provenance_id}/verify")
async def verify_provenance(
    provenance_id: UUID,
    body: VerifyProvenanceRequest,
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: SupplyChainContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.provenance_service.verify(
            VerifyModelProvenanceCommand(
                tenant_id=tenant_id,
                provenance_id=provenance_id,
                retrieval_uri=body.retrieval_uri,
                provider_reported_checksum=body.provider_reported_checksum,
                signature_provider=body.signature_provider,
                signature_location=body.signature_location,
                signing_key_fingerprint=body.signing_key_fingerprint,
                actor_roles=roles,
            )
        )
    except Exception as exc:
        raise _map_error(exc) from exc
    return asdict(dto)


@router.post("/provenances/{provenance_id}/manual-reset")
async def manual_reset(
    provenance_id: UUID,
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: SupplyChainContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.provenance_service.manual_reset(
            ManualResetVerificationCommand(
                tenant_id=tenant_id, provenance_id=provenance_id, actor_roles=roles
            )
        )
    except Exception as exc:
        raise _map_error(exc) from exc
    return asdict(dto)


@router.get("/provenances/{provenance_id}")
async def get_provenance(
    provenance_id: UUID,
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: SupplyChainContainer = Depends(get_container),
) -> dict[str, Any]:
    from ai_supply_chain.application.queries.supply_chain_queries import (
        GetModelProvenanceQuery,
    )

    try:
        dto = await container.query_handler.get_provenance(
            GetModelProvenanceQuery(
                tenant_id=tenant_id,
                provenance_id=provenance_id,
                actor_roles=roles,
            )
        )
    except Exception as exc:
        raise _map_error(exc) from exc
    return asdict(dto)


@router.post("/provenances/{provenance_id}/mbom")
async def build_mbom(
    provenance_id: UUID,
    body: BuildMBOMRequest,
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: SupplyChainContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.mbom_service.build(
            BuildMBOMCommand(
                tenant_id=tenant_id,
                provenance_id=provenance_id,
                components=tuple(body.components),
                actor_roles=roles,
            )
        )
    except Exception as exc:
        raise _map_error(exc) from exc
    return asdict(dto)


@router.post("/discovery-scans")
async def run_discovery_scan(
    body: RunDiscoveryScanRequest,
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: SupplyChainContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.discovery_service.run_scan(
            RunDiscoveryScanCommand(
                tenant_id=tenant_id,
                sources=tuple(body.sources),
                cloud_accounts=tuple(body.cloud_accounts),
                actor_roles=roles,
            )
        )
    except Exception as exc:
        raise _map_error(exc) from exc
    return asdict(dto)


@router.put("/settings/verification-threshold")
async def set_threshold(
    body: SetThresholdRequest,
    tenant_id: UUID = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: SupplyChainContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.provenance_service.set_threshold(
            SetVerificationThresholdCommand(
                tenant_id=tenant_id,
                size_threshold_bytes=body.size_threshold_bytes,
                actor_roles=roles,
            )
        )
    except Exception as exc:
        raise _map_error(exc) from exc
