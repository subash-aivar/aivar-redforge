"""ai_posture HTTP API — Phase 1 + Phase 2."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException

from ai_posture.api.dependencies import get_actor_roles, get_container, get_tenant_id
from ai_posture.api.schemas.posture_schemas import (
    AssessThreatRequest,
    AssignOwnerRequest,
    BulkResolveRequest,
    BulkTriageRequest,
    ClassifyAssetRequest,
    RaiseAlertRequest,
    RegisterAssetRequest,
    SetDiscoveryOnlyModeRequest,
    TriageAlertRequest,
)
from ai_posture.application.commands.posture_commands import (
    ApproveAISystemAssetRegistrationCommand,
    AssessThreatProfileCommand,
    AssignAssetOwnerCommand,
    BulkResolveShadowAIAlertsCommand,
    BulkTriageShadowAIAlertsCommand,
    ClassifyAISystemAssetCommand,
    ComputeRiskScoreCommand,
    CreateThreatProfileCommand,
    DecommissionAISystemAssetCommand,
    RaiseShadowAIAlertCommand,
    RegisterAISystemAssetCommand,
    SetDiscoveryOnlyModeCommand,
    TriageShadowAIAlertCommand,
)
from ai_posture.application.exceptions import (
    ApplicationForbiddenError,
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from ai_posture.domain.exceptions.domain_exceptions import InventoryAssetNotFound
from ai_posture.domain.value_objects.identifiers import TenantId
from ai_posture.infrastructure.container import AIPostureContainer

router = APIRouter(prefix="/ai-posture", tags=["ai-posture"])


def _map_error(exc: Exception) -> HTTPException:
    if isinstance(exc, ApplicationNotFoundError | InventoryAssetNotFound):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, ApplicationForbiddenError):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, ApplicationValidationError):
        return HTTPException(status_code=400, detail=str(exc))
    return HTTPException(status_code=500, detail=str(exc))


@router.post("/assets")
async def register_asset(
    body: RegisterAssetRequest,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AIPostureContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.asset_service.register(
            RegisterAISystemAssetCommand(
                tenant_id=tenant_id,
                asset_ref_id=body.asset_ref_id,
                discovery_source=body.discovery_source,
                data_sensitivity=body.data_sensitivity,
                as_shadow=body.as_shadow,
                actor_roles=roles,
            )
        )
    except Exception as exc:
        raise _map_error(exc) from exc
    return asdict(dto)


@router.post("/assets/{asset_id}/classify")
async def classify_asset(
    asset_id: UUID,
    body: ClassifyAssetRequest,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AIPostureContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.asset_service.classify(
            ClassifyAISystemAssetCommand(
                tenant_id=tenant_id,
                asset_id=asset_id,
                ai_system_kind=body.ai_system_kind,
                actor_roles=roles,
            )
        )
    except Exception as exc:
        raise _map_error(exc) from exc
    return asdict(dto)


@router.post("/assets/{asset_id}/owner")
async def assign_owner(
    asset_id: UUID,
    body: AssignOwnerRequest,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AIPostureContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.asset_service.assign_owner(
            AssignAssetOwnerCommand(
                tenant_id=tenant_id,
                asset_id=asset_id,
                owner_id=body.owner_id,
                owner_display_name=body.owner_display_name,
                actor_roles=roles,
            )
        )
    except Exception as exc:
        raise _map_error(exc) from exc
    return asdict(dto)


@router.post("/assets/{asset_id}/approve")
async def approve_asset(
    asset_id: UUID,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AIPostureContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.asset_service.approve_registration(
            ApproveAISystemAssetRegistrationCommand(
                tenant_id=tenant_id, asset_id=asset_id, actor_roles=roles
            )
        )
    except Exception as exc:
        raise _map_error(exc) from exc
    return asdict(dto)


@router.post("/assets/{asset_id}/decommission")
async def decommission_asset(
    asset_id: UUID,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AIPostureContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.asset_service.decommission(
            DecommissionAISystemAssetCommand(
                tenant_id=tenant_id,
                asset_id=asset_id,
                reason="api",
                actor_roles=roles,
            )
        )
    except Exception as exc:
        raise _map_error(exc) from exc
    return asdict(dto)


@router.get("/assets/{asset_id}")
async def get_asset(
    asset_id: UUID,
    tenant_id: TenantId = Depends(get_tenant_id),
    container: AIPostureContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.asset_service.get(tenant_id, asset_id)
    except Exception as exc:
        raise _map_error(exc) from exc
    return asdict(dto)


@router.post("/shadow-alerts")
async def raise_alert(
    body: RaiseAlertRequest,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AIPostureContainer = Depends(get_container),
) -> dict[str, Any] | None:
    try:
        dto = await container.alert_service.raise_alert(
            RaiseShadowAIAlertCommand(
                tenant_id=tenant_id,
                cloud_account=body.cloud_account,
                resource_identifier=body.resource_identifier,
                service_type=body.service_type,
                region=body.region,
                discovery_source=body.discovery_source,
                actor_roles=roles,
            )
        )
    except Exception as exc:
        raise _map_error(exc) from exc
    return None if dto is None else asdict(dto)


@router.post("/shadow-alerts/{alert_id}/triage")
async def triage_alert(
    alert_id: UUID,
    body: TriageAlertRequest,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AIPostureContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.alert_service.triage(
            TriageShadowAIAlertCommand(
                tenant_id=tenant_id,
                alert_id=alert_id,
                triaged_by=body.triaged_by,
                notes=body.notes,
                actor_roles=roles,
            )
        )
    except Exception as exc:
        raise _map_error(exc) from exc
    return asdict(dto)


@router.post("/shadow-alerts/bulk-triage")
async def bulk_triage(
    body: BulkTriageRequest,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AIPostureContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.alert_service.bulk_triage(
            BulkTriageShadowAIAlertsCommand(
                tenant_id=tenant_id,
                triaged_by=body.triaged_by,
                discovery_source=body.discovery_source,
                cloud_account=body.cloud_account,
                service_type=body.service_type,
                notes=body.notes,
                actor_roles=roles,
            )
        )
    except Exception as exc:
        raise _map_error(exc) from exc
    return asdict(dto)


@router.post("/shadow-alerts/bulk-resolve")
async def bulk_resolve(
    body: BulkResolveRequest,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AIPostureContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.alert_service.bulk_resolve(
            BulkResolveShadowAIAlertsCommand(
                tenant_id=tenant_id,
                alert_ids=tuple(body.alert_ids),
                resolution_action=body.resolution_action,
                confirm_as=body.confirm_as,
                false_positive_reason=body.false_positive_reason,
                actor_roles=roles,
            )
        )
    except Exception as exc:
        raise _map_error(exc) from exc
    return asdict(dto)


@router.get("/shadow-alerts/backlog-age")
async def backlog_age(
    tenant_id: TenantId = Depends(get_tenant_id),
    container: AIPostureContainer = Depends(get_container),
) -> dict[str, Any]:
    dto = await container.alert_service.triage_backlog_age(tenant_id)
    return asdict(dto)


@router.put("/settings/discovery-only-mode")
async def set_discovery_only(
    body: SetDiscoveryOnlyModeRequest,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AIPostureContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        enabled = await container.alert_service.set_discovery_only_mode(
            SetDiscoveryOnlyModeCommand(
                tenant_id=tenant_id, enabled=body.enabled, actor_roles=roles
            )
        )
    except Exception as exc:
        raise _map_error(exc) from exc
    return {"discovery_only_mode": enabled}


@router.post("/assets/{asset_id}/threat-profile")
async def create_threat_profile(
    asset_id: UUID,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AIPostureContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.threat_service.create_profile(
            CreateThreatProfileCommand(tenant_id=tenant_id, asset_id=asset_id, actor_roles=roles)
        )
    except Exception as exc:
        raise _map_error(exc) from exc
    return asdict(dto)


@router.post("/assets/{asset_id}/threat-profile/assess")
async def assess_threat_profile(
    asset_id: UUID,
    body: AssessThreatRequest,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AIPostureContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.threat_service.assess(
            AssessThreatProfileCommand(
                tenant_id=tenant_id,
                asset_id=asset_id,
                evidence_refs=body.evidence_refs,
                actor_roles=roles,
            )
        )
    except Exception as exc:
        raise _map_error(exc) from exc
    return asdict(dto)


@router.post("/assets/{asset_id}/risk-score/compute")
async def compute_risk_score(
    asset_id: UUID,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AIPostureContainer = Depends(get_container),
) -> dict[str, Any]:
    """Async compute endpoint — not a GET/read handler."""
    try:
        dto = await container.risk_service.compute(
            ComputeRiskScoreCommand(tenant_id=tenant_id, asset_id=asset_id, actor_roles=roles)
        )
    except Exception as exc:
        raise _map_error(exc) from exc
    return asdict(dto)


@router.get("/assets/{asset_id}/risk-score")
async def get_risk_score(
    asset_id: UUID,
    tenant_id: TenantId = Depends(get_tenant_id),
    container: AIPostureContainer = Depends(get_container),
) -> dict[str, Any] | None:
    """Read cached snapshot only — never computes synchronously."""
    dto = await container.risk_service.get_latest(tenant_id, asset_id)
    return None if dto is None else asdict(dto)


# --- Phase 5: Compliance + Read Models + Health ---


@router.post("/assets/{asset_id}/compliance/evaluate")
async def evaluate_compliance(
    asset_id: UUID,
    framework_id: str,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AIPostureContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    from ai_posture.application.commands.posture_commands import (
        EvaluateComplianceMappingCommand,
    )

    try:
        items = await container.compliance_service.evaluate(
            EvaluateComplianceMappingCommand(
                tenant_id=tenant_id,
                asset_id=asset_id,
                framework_id=framework_id,
                actor_roles=roles,
            )
        )
    except Exception as exc:
        raise _map_error(exc) from exc
    return [asdict(i) for i in items]


@router.post("/compliance/mappings/{mapping_id}/attest")
async def attest_compliance(
    mapping_id: UUID,
    attestor_id: str,
    satisfied: bool = True,
    notes: str = "",
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AIPostureContainer = Depends(get_container),
) -> dict[str, Any]:
    from ai_posture.application.commands.posture_commands import (
        RecordComplianceAttestationCommand,
    )

    try:
        dto = await container.compliance_service.record_attestation(
            RecordComplianceAttestationCommand(
                tenant_id=tenant_id,
                mapping_id=mapping_id,
                attestor_id=attestor_id,
                satisfied=satisfied,
                notes=notes,
                actor_roles=roles,
            )
        )
    except Exception as exc:
        raise _map_error(exc) from exc
    return asdict(dto)


@router.get("/assets/{asset_id}/compliance")
async def list_compliance(
    asset_id: UUID,
    tenant_id: TenantId = Depends(get_tenant_id),
    container: AIPostureContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    items = await container.compliance_service.list_for_asset(tenant_id, asset_id)
    return [asdict(i) for i in items]


@router.get("/dashboards/inventory")
async def inventory_dashboard(
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AIPostureContainer = Depends(get_container),
) -> dict[str, Any]:
    from ai_posture.application.queries.report_queries import GetInventoryDashboardQuery

    try:
        return await container.report_queries.inventory(
            GetInventoryDashboardQuery(tenant_id=tenant_id, actor_roles=roles)
        )
    except Exception as exc:
        raise _map_error(exc) from exc


@router.get("/dashboards/risk-register")
async def risk_register(
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AIPostureContainer = Depends(get_container),
) -> dict[str, Any]:
    from ai_posture.application.queries.report_queries import GetRiskRegisterQuery

    try:
        return await container.report_queries.risk_register(
            GetRiskRegisterQuery(tenant_id=tenant_id, actor_roles=roles)
        )
    except Exception as exc:
        raise _map_error(exc) from exc


@router.get("/reports/shadow-ai-discovery")
async def shadow_ai_discovery_report(
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AIPostureContainer = Depends(get_container),
) -> dict[str, Any]:
    from ai_posture.application.queries.report_queries import (
        GetShadowAIDiscoveryReportQuery,
    )

    try:
        return await container.report_queries.shadow_discovery(
            GetShadowAIDiscoveryReportQuery(tenant_id=tenant_id, actor_roles=roles)
        )
    except Exception as exc:
        raise _map_error(exc) from exc


@router.get("/reports/compliance-posture")
async def compliance_posture_report(
    framework_id: str,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AIPostureContainer = Depends(get_container),
) -> dict[str, Any]:
    from ai_posture.application.queries.report_queries import GetCompliancePostureQuery

    try:
        return await container.report_queries.compliance_posture(
            GetCompliancePostureQuery(
                tenant_id=tenant_id, framework_id=framework_id, actor_roles=roles
            )
        )
    except Exception as exc:
        raise _map_error(exc) from exc


@router.get("/reports/supply-chain-integrity")
async def supply_chain_integrity_report(
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AIPostureContainer = Depends(get_container),
) -> dict[str, Any]:
    from ai_posture.application.queries.report_queries import (
        GetSupplyChainIntegrityQuery,
    )

    try:
        return await container.report_queries.supply_chain(
            GetSupplyChainIntegrityQuery(tenant_id=tenant_id, actor_roles=roles)
        )
    except Exception as exc:
        raise _map_error(exc) from exc


@router.get("/reports/agent-deviations")
async def agent_deviation_report(
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AIPostureContainer = Depends(get_container),
) -> dict[str, Any]:
    from ai_posture.application.queries.report_queries import (
        GetAgentDeviationReportQuery,
    )

    try:
        return await container.report_queries.agent_deviations(
            GetAgentDeviationReportQuery(tenant_id=tenant_id, actor_roles=roles)
        )
    except Exception as exc:
        raise _map_error(exc) from exc


@router.get("/audit/envelopes/{envelope_id}/human-approval-history")
async def envelope_human_approval_audit(
    envelope_id: UUID,
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AIPostureContainer = Depends(get_container),
) -> dict[str, Any]:
    from ai_posture.application.queries.report_queries import (
        GetEnvelopeApprovalAuditQuery,
    )

    try:
        return await container.report_queries.approval_audit(
            GetEnvelopeApprovalAuditQuery(
                tenant_id=tenant_id, envelope_id=envelope_id, actor_roles=roles
            )
        )
    except Exception as exc:
        raise _map_error(exc) from exc


@router.post("/projections/rebuild")
async def rebuild_projections(
    tenant_id: TenantId = Depends(get_tenant_id),
    roles: tuple[str, ...] = Depends(get_actor_roles),
    container: AIPostureContainer = Depends(get_container),
) -> dict[str, Any]:
    from ai_posture.infrastructure.scheduler.projection_rebuild_worker import (
        run_projection_rebuild,
    )

    try:
        return await run_projection_rebuild(container.rebuild_service, tenant_id, roles)
    except Exception as exc:
        raise _map_error(exc) from exc


@router.get("/health")
async def health(container: AIPostureContainer = Depends(get_container)) -> dict[str, Any]:
    return {
        "status": "ok",
        "context": "ai_posture",
        "phase": 5,
        "read_models": container.read_model_store.status(),
        "graph_nodes": len(getattr(container.graph, "nodes", {})),
        "graph_edges": len(getattr(container.graph, "edges", {})),
    }


@router.get("/health/metrics", response_model=None)
async def prometheus_metrics() -> Any:
    from fastapi.responses import PlainTextResponse

    from ai_posture.infrastructure.observability.metrics import METRICS

    return PlainTextResponse(METRICS.prometheus_text(), media_type="text/plain")
