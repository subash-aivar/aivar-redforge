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

from fastapi import APIRouter, Depends, HTTPException, Query, status
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
