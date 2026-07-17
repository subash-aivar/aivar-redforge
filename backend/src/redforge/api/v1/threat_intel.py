"""Threat Intelligence REST API — M18 live-telemetry expansion pass.

Read endpoints (provider status, health, indicators, enrichments) are
gated by SECURITY_OPERATIONS_READ, the same read-only command-center
permission used throughout M15/M18. Provider configuration (which
changes what external egress happens) and the on-demand
enrich/correlate triggers (which cost real provider quota) require
NETWORK_SECURITY_MANAGE. organization_id is never accepted from the
client — always derived from the verified TenantContext, same
invariant as every other router in this codebase.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from redforge.api.dependencies import (
    get_ioc_correlation_service,
    get_provider_health_service,
    get_threat_intel_config_service,
    get_threat_intel_enrichment_service,
    get_threat_intel_indicator_query_service,
)
from redforge.api.security import TenantContext, require_permission
from redforge.application.threat_intel.config_service import (
    InvalidIndicatorTypeError,
    UnknownProviderError,
)
from redforge.core.exceptions import ValidationError
from redforge.domain.identity.value_objects import Permission

if TYPE_CHECKING:
    from redforge.application.threat_intel.config_service import (
        ThreatIntelProviderConfigService,
    )
    from redforge.application.threat_intel.correlation_service import IocCorrelationService
    from redforge.application.threat_intel.enrichment_service import (
        IndicatorEnrichmentService,
    )
    from redforge.application.threat_intel.health_service import ProviderHealthService
    from redforge.application.threat_intel.indicator_query_service import (
        IndicatorQueryService,
    )

router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])


# ─── Response models ───────────────────────────────────────────────────────


class ProviderConfigResponse(BaseModel):
    provider_name: str
    enabled: bool
    allowed_indicator_types: list[str]
    credential_ref: str | None
    config: dict[str, str]
    is_optional_disclaimer_required: bool
    updated_at: str


class ConfigureProviderRequest(BaseModel):
    enabled: bool
    allowed_indicator_types: list[str] = Field(default_factory=list)
    credential_ref: str | None = None
    config: dict[str, str] | None = None


class ProviderHealthResponse(BaseModel):
    provider_name: str
    configured: bool
    enabled: bool
    status: str
    last_success_at: str | None
    last_error_category: str | None
    last_error_at: str | None
    circuit_state: str


class IndicatorResponse(BaseModel):
    id: str
    indicator: str
    indicator_type: str
    first_seen_at: str
    last_seen_at: str


class EnrichmentResponse(BaseModel):
    provider_name: str
    kind: str
    success: bool
    error_category: str | None
    data: dict[str, Any]
    fetched_at: str
    expires_at: str


class EnrichIpResponse(BaseModel):
    egress_decision: str
    reputation: list[dict[str, Any]]
    geolocation: dict[str, Any] | None
    asn: dict[str, Any] | None
    provider_errors: list[dict[str, Any]]


class CorrelationRunResponse(BaseModel):
    indicators_checked: int
    matches_found: int
    provider_errors: list[dict[str, Any]]


# ─── Provider configuration (Priority 11 — privacy/egress controls) ────────


@router.get("/providers", response_model=list[ProviderConfigResponse])
async def list_providers(
    tenant: TenantContext = Depends(require_permission(Permission.SECURITY_OPERATIONS_READ)),
    service: ThreatIntelProviderConfigService = Depends(get_threat_intel_config_service),
) -> list[ProviderConfigResponse]:
    rows = await service.list_status(tenant.organization_id)
    return [ProviderConfigResponse(**asdict(r)) for r in rows]


@router.put("/providers/{provider_name}", response_model=ProviderConfigResponse)
async def configure_provider(
    provider_name: str,
    body: ConfigureProviderRequest,
    tenant: TenantContext = Depends(require_permission(Permission.NETWORK_SECURITY_MANAGE)),
    service: ThreatIntelProviderConfigService = Depends(get_threat_intel_config_service),
) -> ProviderConfigResponse:
    """Enable/disable a provider and set which indicator types it may be
    queried with. `credential_ref` must be an env-var NAME already
    configured on the server — never a secret value in the request body."""
    try:
        dto = await service.configure(
            organization_id=tenant.organization_id,
            actor_id=tenant.user_id,
            provider_name=provider_name,
            enabled=body.enabled,
            allowed_indicator_types=body.allowed_indicator_types,
            credential_ref=body.credential_ref,
            config=body.config,
        )
    except (UnknownProviderError, InvalidIndicatorTypeError, ValidationError) as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return ProviderConfigResponse(**asdict(dto))


# ─── Provider health (Priority 9) ──────────────────────────────────────────


@router.get("/health", response_model=list[ProviderHealthResponse])
async def get_provider_health(
    tenant: TenantContext = Depends(require_permission(Permission.SECURITY_OPERATIONS_READ)),
    service: ProviderHealthService = Depends(get_provider_health_service),
) -> list[ProviderHealthResponse]:
    rows = await service.get_health(tenant.organization_id)
    return [ProviderHealthResponse(**asdict(r)) for r in rows]


# ─── Indicators & enrichment evidence (Priorities 1/2/4/5 read surface) ────


@router.get("/indicators", response_model=list[IndicatorResponse])
async def list_indicators(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.SECURITY_OPERATIONS_READ)),
    service: IndicatorQueryService = Depends(get_threat_intel_indicator_query_service),
) -> list[IndicatorResponse]:
    rows = await service.list_recent(tenant.organization_id, limit, offset)
    return [IndicatorResponse(**asdict(r)) for r in rows]


@router.get("/indicators/{indicator_id}/enrichments", response_model=list[EnrichmentResponse])
async def get_indicator_enrichments(
    indicator_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.SECURITY_OPERATIONS_READ)),
    service: IndicatorQueryService = Depends(get_threat_intel_indicator_query_service),
) -> list[EnrichmentResponse]:
    rows = await service.list_enrichments(tenant.organization_id, indicator_id)
    return [EnrichmentResponse(**asdict(r)) for r in rows]


# ─── On-demand enrichment / correlation triggers ───────────────────────────


@router.post("/enrich/ip/{ip}", response_model=EnrichIpResponse)
async def enrich_ip(
    ip: str,
    tenant: TenantContext = Depends(require_permission(Permission.NETWORK_SECURITY_MANAGE)),
    service: IndicatorEnrichmentService = Depends(get_threat_intel_enrichment_service),
) -> EnrichIpResponse:
    """Enrich one public IP against every provider this org has enabled.
    A private/internal IP is rejected before any provider is called —
    `egress_decision` reports exactly why."""
    envelope = await service.enrich_ip(tenant.organization_id, ip)
    return EnrichIpResponse(**asdict(envelope))


@router.post("/correlate", response_model=CorrelationRunResponse)
async def run_correlation(
    limit: int = Query(default=50, ge=1, le=200),
    tenant: TenantContext = Depends(require_permission(Permission.NETWORK_SECURITY_MANAGE)),
    service: IocCorrelationService = Depends(get_ioc_correlation_service),
) -> CorrelationRunResponse:
    """Correlate RedForge's own already-observed indicators against
    configured IOC sources. Never invents an indicator to check."""
    summary = await service.correlate_recent(tenant.organization_id, limit)
    return CorrelationRunResponse(**asdict(summary))


# ─── Geographic activity (Priority 1 — real geo map data path) ─────────────


class GeoActivityPointResponse(BaseModel):
    ip: str
    country: str | None
    country_code: str | None
    region: str | None
    city: str | None
    latitude: float | None
    longitude: float | None
    asn: str | None
    network_prefix: str | None
    organization: str | None
    rir_source: str | None
    geo_provider: str | None
    asn_provider: str | None
    first_seen_at: str
    last_seen_at: str
    reputation_providers: list[str]


@router.get("/geo-activity", response_model=list[GeoActivityPointResponse])
async def list_geo_activity(
    limit: int = Query(default=500, ge=1, le=1000),
    tenant: TenantContext = Depends(require_permission(Permission.SECURITY_OPERATIONS_READ)),
) -> list[GeoActivityPointResponse]:
    """Geographic security activity — all public IP indicators with real
    geolocation or ASN/RDAP enrichment. Geolocation is approximate enrichment,
    not proof of attack origin. Returns empty when no enriched indicators exist.
    Never fabricates points."""
    import dataclasses

    from redforge.api.dependencies import _session_factory
    from redforge.application.threat_intel.geo_activity_service import GeoActivityService

    async with _session_factory()() as session:
        service = GeoActivityService(session)
        points = await service.list_geo_activity(tenant.organization_id, limit)
    return [GeoActivityPointResponse(**dataclasses.asdict(p)) for p in points]


# ─── M22 Phase 6 — Sync status / trigger + Navigator + catalog ─────────────


class SyncJobStatusResponse(BaseModel):
    job_key: str
    last_status: str
    last_started_at: str | None
    last_finished_at: str | None
    last_error: str | None
    last_result: dict[str, Any]


class SyncTriggerRequest(BaseModel):
    job_key: str = Field(
        ...,
        pattern="^(attack_technique_sync|vulnerability_sync|indicator_refresh)$",
    )


class CatalogIndicatorResponse(BaseModel):
    id: str
    canonical_key: str
    indicator_type: str
    display_name: str
    confidence: str | None
    risk_state: str
    metadata: dict[str, Any]


@router.get("/sync-status", response_model=list[SyncJobStatusResponse])
async def get_sync_status(
    _tenant: TenantContext = Depends(
        require_permission(Permission.SECURITY_OPERATIONS_READ)
    ),
) -> list[SyncJobStatusResponse]:
    from redforge.api.dependencies import _session_factory
    from redforge.application.threat_intel.sync_orchestration_service import (
        ThreatIntelSyncOrchestrationService,
    )

    service = ThreatIntelSyncOrchestrationService(_session_factory())
    rows = await service.list_status()
    return [SyncJobStatusResponse(**asdict(r)) for r in rows]


@router.post("/sync/trigger", response_model=dict[str, Any])
async def trigger_sync(
    body: SyncTriggerRequest,
    request: Request,
    tenant: TenantContext = Depends(
        require_permission(Permission.NETWORK_SECURITY_MANAGE)
    ),
) -> dict[str, Any]:
    from redforge.api.dependencies import _session_factory, get_feed_connector_registry
    from redforge.application.threat_intel.enrichment_service import (
        IndicatorEnrichmentService,
    )
    from redforge.application.threat_intel.feed_sync_orchestration_service import (
        FeedSyncOrchestrationService,
    )
    from redforge.application.threat_intel.indicator_refresh_worker import (
        IndicatorRefreshWorker,
    )
    from redforge.application.threat_intel.sync_orchestration_service import (
        JOB_ATTACK_TECHNIQUE,
        JOB_INDICATOR_REFRESH,
        JOB_VULNERABILITY,
        ThreatIntelSyncOrchestrationService,
    )
    from redforge.application.threat_intel.threat_fusion_service import (
        ThreatFusionService,
    )

    factory = _session_factory()
    fusion = ThreatFusionService(factory)
    feed_orch = None
    try:
        registry = get_feed_connector_registry(request)
        feed_orch = FeedSyncOrchestrationService(
            factory,
            registry,  # type: ignore[arg-type]
        )
    except Exception:
        feed_orch = None

    service = ThreatIntelSyncOrchestrationService(
        factory,
        feed_orchestration=feed_orch,
        fusion_service=fusion,
    )
    actor = tenant.user_id
    if body.job_key == JOB_ATTACK_TECHNIQUE:
        return await service.run_attack_technique_sync(actor_id=actor)
    if body.job_key == JOB_VULNERABILITY:
        return await service.run_vulnerability_sync(actor_id=actor)
    if body.job_key == JOB_INDICATOR_REFRESH:
        worker = IndicatorRefreshWorker(factory, IndicatorEnrichmentService(factory))
        return await worker.run_once()
    raise HTTPException(status_code=422, detail="Unknown job_key")


@router.get("/catalog/{indicator_type}", response_model=list[CatalogIndicatorResponse])
async def list_catalog_indicators(
    indicator_type: str,
    limit: int = Query(default=100, ge=1, le=400),
    offset: int = Query(default=0, ge=0),
    _tenant: TenantContext = Depends(
        require_permission(Permission.SECURITY_OPERATIONS_READ)
    ),
) -> list[CatalogIndicatorResponse]:
    from redforge.api.dependencies import _session_factory
    from redforge.application.threat_intel.intelligence_catalog_query_service import (
        IntelligenceCatalogQueryService,
    )
    from redforge.domain.threat_intel.fusion_value_objects import FusedIndicatorType

    try:
        kind = FusedIndicatorType(indicator_type)
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid indicator_type: {indicator_type}",
        ) from exc
    service = IntelligenceCatalogQueryService(_session_factory())
    rows = await service.list_by_type(kind, limit=limit, offset=offset)
    return [CatalogIndicatorResponse(**asdict(r)) for r in rows]


@router.get("/attack-navigator-layer")
async def export_attack_navigator_layer(
    investigation_id: str | None = Query(default=None, min_length=26, max_length=26),
    tenant: TenantContext = Depends(
        require_permission(Permission.SECURITY_OPERATIONS_READ)
    ),
) -> dict[str, Any]:
    from redforge.api.dependencies import _session_factory
    from redforge.application.threat_intel.navigator_export_service import (
        AttackNavigatorExportService,
    )

    service = AttackNavigatorExportService(_session_factory())
    layer = await service.export_layer(
        organization_id=tenant.organization_id,
        investigation_id=investigation_id,
    )
    return service.to_navigator_json(layer)


@router.get("/attack-paths", response_model=list[dict[str, Any]])
async def list_tenant_attack_paths(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    tenant: TenantContext = Depends(
        require_permission(Permission.SECURITY_OPERATIONS_READ)
    ),
) -> list[dict[str, Any]]:
    """Tenant-scoped attack-path list (Hardening: ops-read, not platform-only)."""
    from redforge.api.dependencies import _session_factory
    from redforge.application.attack_path.attack_path_service import AttackPathQueryService

    query = AttackPathQueryService(_session_factory())
    paths = await query.list_paths(
        organization_id=tenant.organization_id,
        limit=limit,
        offset=offset,
    )
    return [
        {
            "id": p.id,
            "organization_id": p.organization_id,
            "root_entity_id": p.root_entity_id,
            "root_canonical_key": p.root_canonical_key,
            "terminal_entity_id": p.terminal_entity_id,
            "path_confidence": p.path_confidence.value,
            "technique_coverage": list(p.technique_coverage),
            "attributed_actors": list(p.attributed_actors),
            "step_count": p.step_count,
            "evidence_count": p.evidence_count,
            "max_exposure_score": p.max_exposure_score,
            "status": p.status.value,
            "investigation_id": p.investigation_id,
        }
        for p in paths
    ]


@router.get("/attack-paths/{path_id}", response_model=dict[str, Any])
async def get_tenant_attack_path(
    path_id: str,
    tenant: TenantContext = Depends(
        require_permission(Permission.SECURITY_OPERATIONS_READ)
    ),
) -> dict[str, Any]:
    from redforge.api.dependencies import _session_factory
    from redforge.application.attack_path.attack_path_service import AttackPathQueryService
    from redforge.core.exceptions import NotFoundError

    query = AttackPathQueryService(_session_factory())
    result = await query.get_path(
        organization_id=tenant.organization_id, path_id=path_id
    )
    if result is None:
        raise NotFoundError("AttackPath", path_id)
    path, steps = result
    return {
        "id": path.id,
        "organization_id": path.organization_id,
        "root_entity_id": path.root_entity_id,
        "root_canonical_key": path.root_canonical_key,
        "terminal_entity_id": path.terminal_entity_id,
        "path_confidence": path.path_confidence.value,
        "technique_coverage": list(path.technique_coverage),
        "attributed_actors": list(path.attributed_actors),
        "step_count": path.step_count,
        "evidence_count": path.evidence_count,
        "max_exposure_score": path.max_exposure_score,
        "status": path.status.value,
        "investigation_id": path.investigation_id,
        "steps": [
            {
                "sequence": s.sequence,
                "entity_id": s.entity_id,
                "canonical_key": s.canonical_key,
                "step_type": s.step_type.value,
                "confidence": s.confidence.value,
                "technique_id": s.technique_id,
                "evidence_refs": list(s.evidence_refs),
                "relationship_type": s.relationship_type,
                "kill_chain_phase": s.kill_chain_phase,
                "inferred_from_step": s.inferred_from_step,
                "exposure_score": s.exposure_score,
            }
            for s in steps
        ],
    }
