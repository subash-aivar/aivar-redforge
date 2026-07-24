"""REST API for exposure Phase 1 + Phase 2."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from exposure.api.dependencies import get_actor_roles, get_container, get_tenant_id
from exposure.api.schemas.exposure_schemas import (
    ConfigureWeightsRequest,
    IngestAISystemRiskRequest,
    IngestCloudSecurityRequest,
    IngestConfirmedExploitationRequest,
    IngestDetectionGapRequest,
    IngestVulnerabilityRequest,
    KevStatusChangedRequest,
    QueryExposureScopeRequest,
    RemediateCloudSecurityRequest,
    ResolveVulnerabilityRequest,
    SuppressExposureRequest,
    ThreatActorTargetingUpdatedRequest,
)
from exposure.application.commands.exposure_commands import (
    ConfigureAmplifierWeightsCommand,
    FlushPendingRecomputationsCommand,
    IngestAISystemRiskSignalCommand,
    IngestCloudSecuritySignalCommand,
    IngestConfirmedExploitationCommand,
    IngestDetectionGapSignalCommand,
    IngestVulnerabilitySignalCommand,
    RemediateCloudSecuritySignalCommand,
    ResolveVulnerabilitySignalCommand,
    SuppressExposureRecordCommand,
    VulnerabilityKevStatusChangedCommand,
)
from exposure.application.exceptions import (
    ApplicationForbiddenError,
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from exposure.domain.exceptions.domain_exceptions import ExposureDomainError
from exposure.domain.value_objects.identifiers import TenantId
from exposure.infrastructure.container import ExposureContainer

router = APIRouter(prefix="/exposure", tags=["exposure"])


def _map_error(exc: Exception) -> HTTPException:
    if isinstance(exc, ApplicationForbiddenError):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, ApplicationNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, (ApplicationValidationError, ExposureDomainError)):
        return HTTPException(status_code=400, detail=str(exc))
    return HTTPException(status_code=500, detail="Internal error")


@router.get("/records/{record_id}")
async def get_record(
    record_id: UUID,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.exposure_service.get_record(tenant_id, record_id, roles)
        return asdict(dto)
    except Exception as exc:
        raise _map_error(exc) from exc


@router.get("/assets/{asset_ref_id}/records")
async def list_records_by_asset(
    asset_ref_id: UUID,
    status: str | None = Query(default=None),
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    try:
        rows = await container.exposure_service.list_by_asset(
            tenant_id, asset_ref_id, roles, status_filter=status
        )
        return [asdict(r) for r in rows]
    except Exception as exc:
        raise _map_error(exc) from exc


@router.get("/assets/{asset_ref_id}/score")
async def get_latest_score(
    asset_ref_id: UUID,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureContainer = Depends(get_container),
) -> dict[str, Any] | None:
    try:
        dto = await container.exposure_service.get_latest_score(tenant_id, asset_ref_id, roles)
        return asdict(dto) if dto else None
    except Exception as exc:
        raise _map_error(exc) from exc


@router.get("/weights")
async def get_weights(
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return asdict(await container.exposure_service.get_weights(tenant_id, roles))
    except Exception as exc:
        raise _map_error(exc) from exc


@router.put("/weights")
async def configure_weights(
    body: ConfigureWeightsRequest,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.exposure_service.configure_weights(
            ConfigureAmplifierWeightsCommand(
                tenant_id=tenant_id,
                weights=body.weights,
                change_rationale=body.change_rationale,
                changed_by=body.changed_by,
                actor_roles=roles,
            )
        )
        return asdict(dto)
    except Exception as exc:
        raise _map_error(exc) from exc


@router.post("/records/{record_id}/suppress")
async def suppress_record(
    record_id: UUID,
    body: SuppressExposureRequest,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.exposure_service.suppress(
            SuppressExposureRecordCommand(
                tenant_id=tenant_id,
                record_id=record_id,
                justification=body.justification,
                suppressed_by=body.suppressed_by,
                actor_roles=roles,
            )
        )
        return asdict(dto)
    except Exception as exc:
        raise _map_error(exc) from exc


@router.get("/profile")
async def get_profile(
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return asdict(await container.exposure_service.get_profile(tenant_id, roles))
    except Exception as exc:
        raise _map_error(exc) from exc


@router.post("/internal/signals/vulnerability")
async def ingest_vulnerability(
    body: IngestVulnerabilityRequest,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureContainer = Depends(get_container),
) -> dict[str, Any] | None:
    try:
        dto = await container.ingestion.ingest_vulnerability(
            IngestVulnerabilitySignalCommand(
                tenant_id=tenant_id,
                event_id=body.event_id,
                vulnerability_instance_id=body.vulnerability_instance_id,
                asset_ref_id=body.asset_ref_id,
                cvss_base=body.cvss_base,
                is_kev=body.is_kev,
                technique_refs=tuple(body.technique_refs),
                cve_ids=tuple(body.cve_ids),
                asset_classes=tuple(body.asset_classes),
                actor_roles=roles,
            )
        )
        return asdict(dto) if dto else None
    except Exception as exc:
        raise _map_error(exc) from exc


@router.post("/internal/signals/vulnerability/resolve")
async def resolve_vulnerability(
    body: ResolveVulnerabilityRequest,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureContainer = Depends(get_container),
) -> dict[str, Any] | None:
    try:
        dto = await container.ingestion.resolve_vulnerability(
            ResolveVulnerabilitySignalCommand(
                tenant_id=tenant_id,
                event_id=body.event_id,
                vulnerability_instance_id=body.vulnerability_instance_id,
                actor_roles=roles,
            )
        )
        return asdict(dto) if dto else None
    except Exception as exc:
        raise _map_error(exc) from exc


@router.post("/internal/signals/vulnerability/kev")
async def kev_status_changed(
    body: KevStatusChangedRequest,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureContainer = Depends(get_container),
) -> dict[str, Any] | None:
    try:
        dto = await container.ingestion.kev_status_changed(
            VulnerabilityKevStatusChangedCommand(
                tenant_id=tenant_id,
                event_id=body.event_id,
                vulnerability_instance_id=body.vulnerability_instance_id,
                is_kev=body.is_kev,
                actor_roles=roles,
            )
        )
        return asdict(dto) if dto else None
    except Exception as exc:
        raise _map_error(exc) from exc


@router.post("/internal/signals/cloud-security")
async def ingest_cloud_security(
    body: IngestCloudSecurityRequest,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureContainer = Depends(get_container),
) -> dict[str, Any] | None:
    try:
        dto = await container.ingestion.ingest_cloud_security(
            IngestCloudSecuritySignalCommand(
                tenant_id=tenant_id,
                event_id=body.event_id,
                misconfiguration_id=body.misconfiguration_id,
                asset_ref_id=body.asset_ref_id,
                severity_score=body.severity_score,
                has_internet_exposure=body.has_internet_exposure,
                actor_roles=roles,
            )
        )
        return asdict(dto) if dto else None
    except Exception as exc:
        raise _map_error(exc) from exc


@router.post("/internal/signals/cloud-security/remediate")
async def remediate_cloud_security(
    body: RemediateCloudSecurityRequest,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureContainer = Depends(get_container),
) -> dict[str, Any] | None:
    try:
        dto = await container.ingestion.remediate_cloud_security(
            RemediateCloudSecuritySignalCommand(
                tenant_id=tenant_id,
                event_id=body.event_id,
                misconfiguration_id=body.misconfiguration_id,
                actor_roles=roles,
            )
        )
        return asdict(dto) if dto else None
    except Exception as exc:
        raise _map_error(exc) from exc


@router.post("/internal/signals/detection-gap")
async def ingest_detection_gap(
    body: IngestDetectionGapRequest,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        count = await container.ingestion.ingest_detection_gap(
            IngestDetectionGapSignalCommand(
                tenant_id=tenant_id,
                event_id=body.event_id,
                gap_id=body.gap_id,
                technique_ref=body.technique_ref,
                asset_ref_id=body.asset_ref_id,
                is_open=body.is_open,
                actor_roles=roles,
            )
        )
        return {"attached_count": count}
    except Exception as exc:
        raise _map_error(exc) from exc


@router.post("/internal/signals/ai-system-risk")
async def ingest_ai_system_risk(
    body: IngestAISystemRiskRequest,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        count = await container.ingestion.ingest_ai_system_risk(
            IngestAISystemRiskSignalCommand(
                tenant_id=tenant_id,
                event_id=body.event_id,
                asset_ref_id=body.asset_ref_id,
                exposure_level=body.exposure_level,
                amplifier_weight=body.amplifier_weight,
                profile_ref=body.profile_ref,
                actor_roles=roles,
            )
        )
        return {"attached_count": count}
    except Exception as exc:
        raise _map_error(exc) from exc


@router.post("/internal/signals/confirmed-exploitation")
async def ingest_confirmed_exploitation(
    body: IngestConfirmedExploitationRequest,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        count = await container.ingestion.ingest_confirmed_exploitation(
            IngestConfirmedExploitationCommand(
                tenant_id=tenant_id,
                event_id=body.event_id,
                asset_ref_id=body.asset_ref_id,
                evidence_ref=body.evidence_ref,
                cve_id=body.cve_id,
                actor_roles=roles,
            )
        )
        return {"attached_count": count}
    except Exception as exc:
        raise _map_error(exc) from exc


@router.post("/internal/events/threat-actor-targeting")
async def threat_actor_targeting_updated(
    body: ThreatActorTargetingUpdatedRequest,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureContainer = Depends(get_container),
) -> dict[str, Any]:
    del roles
    try:
        attached = await container.threat_subscriber.on_threat_actor_asset_class_targeting_updated(
            tenant_id=tenant_id,
            event_id=body.event_id,
            threat_actor_ref=body.threat_actor_ref,
            targeted_cve_ids=body.targeted_cve_ids,
            targeted_asset_classes=body.targeted_asset_classes,
            targeted_techniques=body.targeted_techniques,
            targeted_iocs=body.targeted_iocs,
            targeting_confidence=body.targeting_confidence,
        )
        return {"attached_count": attached}
    except Exception as exc:
        raise _map_error(exc) from exc


@router.post("/admin/threat-intel/poll")
async def poll_threat_intel(
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureContainer = Depends(get_container),
) -> dict[str, Any]:
    from exposure.application._auth import require_at_least
    from exposure.domain.value_objects.enums import ExposureRole

    try:
        require_at_least(roles, ExposureRole.ANALYST)
        return await container.threat_poll_scheduler.run_for_tenant(tenant_id)
    except Exception as exc:
        raise _map_error(exc) from exc


@router.post("/admin/threat-intel/bootstrap")
async def bootstrap_threat_intel(
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureContainer = Depends(get_container),
) -> dict[str, Any]:
    from exposure.application._auth import require_at_least
    from exposure.domain.value_objects.enums import ExposureRole

    try:
        require_at_least(roles, ExposureRole.ANALYST)
        return await container.threat_sync.bootstrap_if_cold(tenant_id)
    except Exception as exc:
        raise _map_error(exc) from exc


@router.get("/threat-intel/targeting")
async def get_threat_actor_targeting(
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.threat_query.get_threat_actor_targeting(tenant_id, roles)
    except Exception as exc:
        raise _map_error(exc) from exc


@router.post("/scope/query")
async def query_exposure_scope(
    body: QueryExposureScopeRequest,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return await container.scope_service.query_scope(
            tenant_id=tenant_id,
            actor_roles=roles,
            max_assets=body.max_assets,
            min_exposure_score=body.min_exposure_score,
            amplifier_filter=body.amplifier_filter,
            asset_kind_filter=body.asset_kind_filter,
            include_stale_scores=body.include_stale_scores,
        )
    except Exception as exc:
        raise _map_error(exc) from exc


@router.post("/admin/pending/flush")
async def flush_pending(
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        flushed = await container.exposure_service.flush_pending(
            FlushPendingRecomputationsCommand(tenant_id=tenant_id, actor_roles=roles)
        )
        return {"flushed_asset_ids": flushed}
    except Exception as exc:
        raise _map_error(exc) from exc


@router.post("/admin/pipeline/run")
async def run_score_pipeline(
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: ExposureContainer = Depends(get_container),
) -> dict[str, Any]:
    """Admin escape hatch: dispatch + compute with zero debounce (ops/testing)."""
    from exposure.application._auth import require_at_least
    from exposure.domain.value_objects.enums import ExposureRole

    try:
        require_at_least(roles, ExposureRole.ADMIN)
        del tenant_id
        computed = await container.score_worker.run_pipeline_once(
            container.debouncer, container.dispatcher, debounce_seconds=0
        )
        return {"computed": computed}
    except Exception as exc:
        raise _map_error(exc) from exc


@router.get("/health")
async def health(container: ExposureContainer = Depends(get_container)) -> dict[str, Any]:
    return {
        "status": "ok",
        "context": "exposure",
        "phase": 4,
        "pipeline_paused": container.dispatcher.paused,
        "threat_poll_last_run_at": container.threat_poll_scheduler.last_run_at,
    }
