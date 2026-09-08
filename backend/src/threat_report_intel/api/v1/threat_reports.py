"""Threat-Report Intelligence API router, mirroring
`infrastructure_intel.api.v1.infrastructure`'s exact ownership-based
authorization shape: `POST /observations/tenant` and
`POST /observations/global` remain two explicit routes (ownership must
be stated up front — no existing ThreatReport record to load yet);
`GET /` (tenant list) and `GET /global` (global list) are unambiguous,
non-duplicated paths; every `{threat_report_id}` operation is ONE
canonical route, authorizing dynamically from the *loaded record's own
ownership scope* (`ThreatReport.tenant_id`, resolved via
`ThreatReportApplicationService.get_scope`) rather than from which URL
prefix the caller happened to use:

    scope = await svc.get_scope(threat_report_id)  # TenantId|None; 404
    if scope is None:                      # global
        require platform.has_permission(...)   # else 403
    else:                                  # tenant-owned
        require tenant is not None and tenant.organization_id == str(scope)
                                                 # else 404 (cross-tenant)
        require tenant.has_permission(...)      # else 403

The URL prefix is `/threat-report-intel` — deliberately distinct from
anything `reporting`, `analytics` or `regulatory_notification` might
claim, since RedForge's own generated reports and outbound regulatory
filings are unrelated concepts that merely share the English word
"report".

There is deliberately NO relationship route here. Linking a report to
the actors, campaigns, malware, tools, infrastructure, attack patterns
or IOCs it describes belongs exclusively to `intelligence_relationships`
— which (as of M51.9 Phase H1) defines seven `THREAT_REPORT_TO_*`
`RelationshipType` values and supports these links today via its own
API/application service. This context does not gain a relationship
route just because that vocabulary now exists: adding one here would
duplicate a certified capability. See the `ThreatReport` aggregate's
module docstring for the full picture.

`deprecate`/`revoke`/`supersede`/`reactivate` move RedForge's own RECORD
lifecycle — never a claim about the publication itself.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, Query, Response, status

from redforge.api.security import (
    TenantContext,
    require_permission,
    require_platform_permission,
)
from redforge.domain.identity.value_objects import Permission
from redforge.domain.platform_identity.value_objects import PlatformPermission
from threat_report_intel.api.dependencies import (
    OptionalTenantContextDep,
    PlatformContextDep,
    TenantIdDep,
    ThreatReportServiceDep,
)
from threat_report_intel.api.schemas.threat_report_schemas import (
    AddEvidenceCitationRequest,
    AddReferenceRequest,
    AddSourceAttributionRequest,
    LifecycleTransitionRequest,
    ObserveThreatReportRequest,
    PaginatedThreatReportListResponse,
    PublisherResponse,
    ReportMetadataResponse,
    SourceAttributionRequest,
    SourceAttributionResponse,
    SupersedeThreatReportRequest,
    ThreatReportDetailResponse,
    ThreatReportReferenceRequest,
    ThreatReportReferenceResponse,
    ThreatReportSummaryResponse,
    VersionRecordResponse,
)
from threat_report_intel.application.commands.threat_report_commands import (
    AddEvidenceCitationCommand,
    AddReferenceCommand,
    AddSourceAttributionCommand,
    DeprecateThreatReportCommand,
    ObserveThreatReportCommand,
    PublisherInput,
    ReactivateThreatReportCommand,
    ReportMetadataInput,
    RevokeThreatReportCommand,
    SourceAttributionInput,
    SupersedeThreatReportCommand,
    ThreatReportReferenceInput,
)
from threat_report_intel.application.exceptions import (
    ApplicationForbiddenError,
    ApplicationNotFoundError,
)
from threat_report_intel.application.queries.threat_report_queries import (
    DEFAULT_LIST_LIMIT,
    MAX_LIST_LIMIT,
    GetThreatReportQuery,
    ListThreatReportsQuery,
)

if TYPE_CHECKING:
    from redforge.api.security import PlatformContext
    from threat_report_intel.application.dtos.threat_report_dtos import (
        ThreatReportDetailDTO,
        ThreatReportSummaryDTO,
    )
    from threat_report_intel.application.services.threat_report_application_service import (
        ThreatReportApplicationService,
    )
    from threat_report_intel.domain.value_objects.identifiers import TenantId

threat_report_router = APIRouter()


async def _authorize_scope(
    threat_report_id: str,
    svc: ThreatReportApplicationService,
    tenant: TenantContext | None,
    platform: PlatformContext,
    *,
    tenant_permission: Permission,
    platform_permission: PlatformPermission,
) -> TenantId | None:
    """The single ownership-based authorization decision every canonical
    `{threat_report_id}` route uses. Raises `ApplicationNotFoundError`
    (404) if the record doesn't exist, `ApplicationForbiddenError` (403)
    if the caller lacks the required authority for the resource's actual
    scope, or returns the `tenant_id` to use for the real, authorized
    operation (`None` for global)."""
    scope = await svc.get_scope(threat_report_id)
    if scope is None:
        if not platform.has_permission(platform_permission):
            raise ApplicationForbiddenError(platform_permission.value)
        return None
    if tenant is None or tenant.organization_id != str(scope):
        raise ApplicationNotFoundError("ThreatReport", threat_report_id)
    if not tenant.has_permission(tenant_permission):
        raise ApplicationForbiddenError(tenant_permission.value)
    return scope


def _to_attribution_input(attribution: SourceAttributionRequest) -> SourceAttributionInput:
    return SourceAttributionInput(
        source_system=attribution.source_system,
        reference=attribution.reference,
        observed_at=attribution.observed_at,
        confidence=attribution.confidence,
        notes=attribution.notes,
    )


def _to_reference_input(reference: ThreatReportReferenceRequest) -> ThreatReportReferenceInput:
    return ThreatReportReferenceInput(
        url_or_citation=reference.url_or_citation, description=reference.description
    )


def _detail_response(dto: ThreatReportDetailDTO) -> ThreatReportDetailResponse:
    return ThreatReportDetailResponse(
        threat_report_id=dto.threat_report_id,
        tenant_id=dto.tenant_id,
        title=dto.title,
        canonical_title=dto.canonical_title,
        publisher=PublisherResponse(
            organization_name=dto.publisher.organization_name,
            contact=dto.publisher.contact,
        ),
        publication_date=dto.publication_date,
        report_metadata=ReportMetadataResponse(
            report_type=dto.report_metadata.report_type,
            tlp_marking=dto.report_metadata.tlp_marking,
            external_report_id=dto.report_metadata.external_report_id,
        ),
        severity=dto.severity,
        confidence=dto.confidence,
        executive_summary=dto.executive_summary,
        technical_summary=dto.technical_summary,
        lifecycle_status=dto.lifecycle_status,
        superseded_by=dto.superseded_by,
        created_at=dto.created_at,
        updated_at=dto.updated_at,
        references=[
            ThreatReportReferenceResponse(
                url_or_citation=r.url_or_citation, description=r.description
            )
            for r in dto.references
        ],
        evidence_citations=list(dto.evidence_citations),
        source_attributions=[
            SourceAttributionResponse(
                source_system=a.source_system,
                reference=a.reference,
                observed_at=a.observed_at,
                confidence=a.confidence,
                notes=a.notes,
            )
            for a in dto.source_attributions
        ],
        version_history=[
            VersionRecordResponse(
                version=v.version,
                changed_at=v.changed_at,
                change_summary=v.change_summary,
                source=v.source,
            )
            for v in dto.version_history
        ],
    )


def _summary_response(dto: ThreatReportSummaryDTO) -> ThreatReportSummaryResponse:
    return ThreatReportSummaryResponse(
        threat_report_id=dto.threat_report_id,
        tenant_id=dto.tenant_id,
        title=dto.title,
        canonical_title=dto.canonical_title,
        publisher=dto.publisher,
        publication_date=dto.publication_date,
        report_type=dto.report_type,
        tlp_marking=dto.tlp_marking,
        severity=dto.severity,
        confidence=dto.confidence,
        lifecycle_status=dto.lifecycle_status,
        created_at=dto.created_at,
        updated_at=dto.updated_at,
        reference_count=dto.reference_count,
        evidence_citation_count=dto.evidence_citation_count,
        source_attribution_count=dto.source_attribution_count,
    )


def _observe_command(
    body: ObserveThreatReportRequest, tenant_id: TenantId | None
) -> ObserveThreatReportCommand:
    return ObserveThreatReportCommand(
        tenant_id=tenant_id,
        title=body.title,
        publisher=PublisherInput(
            organization_name=body.publisher.organization_name,
            contact=body.publisher.contact,
        ),
        publication_date=body.publication_date,
        report_metadata=ReportMetadataInput(
            report_type=body.report_metadata.report_type,
            tlp_marking=body.report_metadata.tlp_marking,
            external_report_id=body.report_metadata.external_report_id,
        ),
        executive_summary=body.executive_summary,
        technical_summary=body.technical_summary,
        severity=body.severity,
        confidence=body.confidence,
        references=tuple(_to_reference_input(r) for r in body.references),
    )


# ── Observation (ownership stated explicitly — no existing record) ──────


@threat_report_router.post(
    "/observations/tenant",
    status_code=status.HTTP_201_CREATED,
    response_model=ThreatReportDetailResponse,
    summary="Observe a tenant-scoped published ThreatReport",
    description=(
        "Tenant-scoped threat-report observation. `title` is kept as the "
        "analyst's real display value; its normalized `canonical_title` "
        "is deduplicated within this tenant's scope — never creates a "
        "second identity for the same normalized title."
    ),
)
async def observe_tenant_threat_report(
    body: ObserveThreatReportRequest,
    response: Response,
    tenant_id: TenantIdDep,
    svc: ThreatReportServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.THREAT_REPORT_OBSERVE)),
) -> ThreatReportDetailResponse:
    dto = await svc.observe(_observe_command(body, tenant_id))
    response.headers["Location"] = f"/api/v1/threat-report-intel/{dto.threat_report_id}"
    return _detail_response(dto)


@threat_report_router.post(
    "/observations/global",
    status_code=status.HTTP_201_CREATED,
    response_model=ThreatReportDetailResponse,
    summary="Observe a global published ThreatReport (platform authority required)",
    description=(
        "Global, RedForge-curated ThreatReport record. Requires platform "
        "authority (PLATFORM_THREAT_REPORT_MANAGE) — no organization "
        "OWNER/ADMIN/SECURITY_MANAGER membership satisfies this."
    ),
)
async def observe_global_threat_report(
    body: ObserveThreatReportRequest,
    response: Response,
    svc: ThreatReportServiceDep,
    _platform: PlatformContext = Depends(
        require_platform_permission(PlatformPermission.PLATFORM_THREAT_REPORT_MANAGE)
    ),
) -> ThreatReportDetailResponse:
    dto = await svc.observe(_observe_command(body, None))
    response.headers["Location"] = f"/api/v1/threat-report-intel/{dto.threat_report_id}"
    return _detail_response(dto)


# ── Lists (unambiguous, distinct paths) ─────────────────────────────────


@threat_report_router.get(
    "",
    response_model=PaginatedThreatReportListResponse,
    summary="List this tenant's ThreatReport records",
)
async def list_tenant_threat_reports(
    tenant_id: TenantIdDep,
    svc: ThreatReportServiceDep,
    lifecycle_status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    tlp_marking: str | None = Query(default=None),
    limit: int = Query(default=DEFAULT_LIST_LIMIT, ge=1, le=MAX_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
    _tenant: TenantContext = Depends(require_permission(Permission.THREAT_REPORT_READ)),
) -> PaginatedThreatReportListResponse:
    items = await svc.list(
        ListThreatReportsQuery(
            tenant_id=tenant_id,
            lifecycle_status=lifecycle_status,
            severity=severity,
            tlp_marking=tlp_marking,
            limit=limit,
            offset=offset,
        )
    )
    summaries = [_summary_response(i) for i in items]
    return PaginatedThreatReportListResponse(
        items=summaries, count=len(summaries), limit=limit, offset=offset
    )


@threat_report_router.get(
    "/global",
    response_model=PaginatedThreatReportListResponse,
    summary="List global ThreatReport records",
)
async def list_global_threat_reports(
    svc: ThreatReportServiceDep,
    lifecycle_status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    tlp_marking: str | None = Query(default=None),
    limit: int = Query(default=DEFAULT_LIST_LIMIT, ge=1, le=MAX_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
    _platform: PlatformContext = Depends(
        require_platform_permission(PlatformPermission.PLATFORM_THREAT_REPORT_READ)
    ),
) -> PaginatedThreatReportListResponse:
    items = await svc.list(
        ListThreatReportsQuery(
            tenant_id=None,
            lifecycle_status=lifecycle_status,
            severity=severity,
            tlp_marking=tlp_marking,
            limit=limit,
            offset=offset,
        )
    )
    summaries = [_summary_response(i) for i in items]
    return PaginatedThreatReportListResponse(
        items=summaries, count=len(summaries), limit=limit, offset=offset
    )


# ── Canonical single routes per {threat_report_id} operation ───────────


@threat_report_router.get(
    "/{threat_report_id}",
    response_model=ThreatReportDetailResponse,
    summary="Get a ThreatReport record",
)
async def get_threat_report(
    threat_report_id: str,
    svc: ThreatReportServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> ThreatReportDetailResponse:
    tenant_id = await _authorize_scope(
        threat_report_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.THREAT_REPORT_READ,
        platform_permission=PlatformPermission.PLATFORM_THREAT_REPORT_READ,
    )
    dto = await svc.get(
        GetThreatReportQuery(tenant_id=tenant_id, threat_report_id=threat_report_id)
    )
    return _detail_response(dto)


@threat_report_router.post(
    "/{threat_report_id}/references",
    response_model=ThreatReportDetailResponse,
    summary="Add a reference (URL or citation)",
)
async def add_reference(
    threat_report_id: str,
    body: AddReferenceRequest,
    svc: ThreatReportServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> ThreatReportDetailResponse:
    tenant_id = await _authorize_scope(
        threat_report_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.THREAT_REPORT_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_THREAT_REPORT_MANAGE,
    )
    dto = await svc.add_reference(
        AddReferenceCommand(
            tenant_id=tenant_id,
            threat_report_id=threat_report_id,
            reference=_to_reference_input(body.reference),
        )
    )
    return _detail_response(dto)


@threat_report_router.post(
    "/{threat_report_id}/evidence-citations",
    response_model=ThreatReportDetailResponse,
    summary="Add an evidence citation",
)
async def add_evidence_citation(
    threat_report_id: str,
    body: AddEvidenceCitationRequest,
    svc: ThreatReportServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> ThreatReportDetailResponse:
    tenant_id = await _authorize_scope(
        threat_report_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.THREAT_REPORT_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_THREAT_REPORT_MANAGE,
    )
    dto = await svc.add_evidence_citation(
        AddEvidenceCitationCommand(
            tenant_id=tenant_id,
            threat_report_id=threat_report_id,
            citation=body.citation,
        )
    )
    return _detail_response(dto)


@threat_report_router.post(
    "/{threat_report_id}/source-attributions",
    response_model=ThreatReportDetailResponse,
    summary="Add a source attribution",
)
async def add_source_attribution(
    threat_report_id: str,
    body: AddSourceAttributionRequest,
    svc: ThreatReportServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> ThreatReportDetailResponse:
    tenant_id = await _authorize_scope(
        threat_report_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.THREAT_REPORT_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_THREAT_REPORT_MANAGE,
    )
    dto = await svc.add_source_attribution(
        AddSourceAttributionCommand(
            tenant_id=tenant_id,
            threat_report_id=threat_report_id,
            attribution=_to_attribution_input(body.attribution),
        )
    )
    return _detail_response(dto)


@threat_report_router.patch(
    "/{threat_report_id}/deprecate",
    response_model=ThreatReportDetailResponse,
    summary="Deprecate a ThreatReport RECORD",
)
async def deprecate_threat_report(
    threat_report_id: str,
    body: LifecycleTransitionRequest,
    svc: ThreatReportServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> ThreatReportDetailResponse:
    tenant_id = await _authorize_scope(
        threat_report_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.THREAT_REPORT_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_THREAT_REPORT_MANAGE,
    )
    dto = await svc.deprecate(
        DeprecateThreatReportCommand(
            tenant_id=tenant_id,
            threat_report_id=threat_report_id,
            evidence=_to_attribution_input(body.evidence),
        )
    )
    return _detail_response(dto)


@threat_report_router.patch(
    "/{threat_report_id}/revoke",
    response_model=ThreatReportDetailResponse,
    summary="Revoke a ThreatReport RECORD",
)
async def revoke_threat_report(
    threat_report_id: str,
    body: LifecycleTransitionRequest,
    svc: ThreatReportServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> ThreatReportDetailResponse:
    tenant_id = await _authorize_scope(
        threat_report_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.THREAT_REPORT_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_THREAT_REPORT_MANAGE,
    )
    dto = await svc.revoke(
        RevokeThreatReportCommand(
            tenant_id=tenant_id,
            threat_report_id=threat_report_id,
            evidence=_to_attribution_input(body.evidence),
        )
    )
    return _detail_response(dto)


@threat_report_router.patch(
    "/{threat_report_id}/supersede",
    response_model=ThreatReportDetailResponse,
    summary="Supersede a ThreatReport RECORD",
)
async def supersede_threat_report(
    threat_report_id: str,
    body: SupersedeThreatReportRequest,
    svc: ThreatReportServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> ThreatReportDetailResponse:
    tenant_id = await _authorize_scope(
        threat_report_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.THREAT_REPORT_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_THREAT_REPORT_MANAGE,
    )
    dto = await svc.supersede(
        SupersedeThreatReportCommand(
            tenant_id=tenant_id,
            threat_report_id=threat_report_id,
            superseded_by=body.superseded_by,
            evidence=_to_attribution_input(body.evidence),
        )
    )
    return _detail_response(dto)


@threat_report_router.patch(
    "/{threat_report_id}/reactivate",
    response_model=ThreatReportDetailResponse,
    summary="Reactivate a ThreatReport RECORD",
)
async def reactivate_threat_report(
    threat_report_id: str,
    body: LifecycleTransitionRequest,
    svc: ThreatReportServiceDep,
    tenant: OptionalTenantContextDep,
    platform: PlatformContextDep,
) -> ThreatReportDetailResponse:
    tenant_id = await _authorize_scope(
        threat_report_id,
        svc,
        tenant,
        platform,
        tenant_permission=Permission.THREAT_REPORT_MANAGE,
        platform_permission=PlatformPermission.PLATFORM_THREAT_REPORT_MANAGE,
    )
    dto = await svc.reactivate(
        ReactivateThreatReportCommand(
            tenant_id=tenant_id,
            threat_report_id=threat_report_id,
            evidence=_to_attribution_input(body.evidence),
        )
    )
    return _detail_response(dto)
