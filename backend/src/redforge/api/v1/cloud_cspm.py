"""M26 Phase 4 CSPM APIs — evaluations, findings, policies, summaries."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, Field

from redforge.api.dependencies import get_cspm_assessment_service
from redforge.api.security import TenantContext, require_permission
from redforge.application.cloud_security.cspm.dtos import (
    EvaluateAssetCommand,
    GetEvaluationQuery,
    GetFindingQuery,
    GetPolicyQuery,
    ListEvaluationsQuery,
    ListFindingsQuery,
    ListPoliciesQuery,
    SummaryQuery,
    TriggerCSPMEvaluationCommand,
    UpdateFindingStatusCommand,
)
from redforge.domain.identity.value_objects import Permission

if TYPE_CHECKING:
    from redforge.application.cloud_security.cspm.assessment_service import (
        CSPMAssessmentService,
    )

router = APIRouter(prefix="/cloud-foundation", tags=["cloud-foundation"])


class TriggerEvaluationRequest(BaseModel):
    cloud_account_id: UUID | None = None
    policy_ids: list[str] = Field(default_factory=list)
    incremental: bool = False


class UpdateFindingStatusRequest(BaseModel):
    status: str
    reason: str = ""
    suppressed_until: datetime | None = None
    accepted_by: str | None = None


class ComplianceRefResponse(BaseModel):
    framework_key: str
    requirement_ref: str
    resolved: bool = False


class FindingEvidenceResponse(BaseModel):
    evidence_id: str
    path: str
    expected: str
    actual: str
    message: str


class CSPMFindingResponse(BaseModel):
    finding_id: UUID
    organization_id: str
    cloud_asset_id: UUID
    policy_id: str
    rule_id: str
    severity: str
    confidence: str
    title: str
    description: str
    status: str
    config_hash: str
    fingerprint: str
    first_seen_at: str
    last_seen_at: str
    detected_at: str
    resolved_at: str | None
    reopened_at: str | None
    suppressed_until: str | None
    accepted_by: str | None
    accepted_reason: str | None
    created_at: str
    updated_at: str
    version: int
    compliance_mapping: list[ComplianceRefResponse] = Field(default_factory=list)
    evidence: list[FindingEvidenceResponse] = Field(default_factory=list)
    remediation: dict[str, Any] = Field(default_factory=dict)


class CSPMFindingPageResponse(BaseModel):
    items: list[CSPMFindingResponse]
    page: int
    size: int
    total: int


class CSPMPolicyResponse(BaseModel):
    policy_id: str
    rule_id: str
    title: str
    description: str
    severity: str
    version: str
    provider_types: list[str]
    asset_types: list[str]
    enabled: bool
    evaluation_strategy: str
    inherits_from: str | None
    metadata: dict[str, Any]
    remediation: dict[str, Any]
    compliance_mapping: list[ComplianceRefResponse]
    rule: dict[str, Any]
    created_at: str
    updated_at: str


class EvaluationResultResponse(BaseModel):
    policy_id: str
    rule_id: str
    cloud_asset_id: str
    passed: bool
    severity: str
    title: str
    message: str
    duration_ms: int


class CSPMEvaluationResponse(BaseModel):
    evaluation_id: UUID
    organization_id: str
    cloud_account_id: str | None
    status: str
    assets_evaluated: int
    policies_evaluated: int
    findings_opened: int
    findings_resolved: int
    diagnostics: dict[str, Any]
    started_at: str
    completed_at: str | None
    error_message: str | None
    results: list[EvaluationResultResponse] = Field(default_factory=list)


class CSPMEvaluationPageResponse(BaseModel):
    items: list[CSPMEvaluationResponse]
    page: int
    size: int
    total: int


class FindingSummaryResponse(BaseModel):
    organization_id: str
    open_by_severity: dict[str, int]
    total_open: int


class ComplianceSummaryResponse(BaseModel):
    organization_id: str
    mapped_frameworks: list[str]
    mapped_controls: int
    unresolved_refs: int
    open_findings_with_mapping: int


def _finding_response(dto: Any) -> CSPMFindingResponse:
    return CSPMFindingResponse(
        finding_id=UUID(str(dto.finding_id)),
        organization_id=str(dto.organization_id),
        cloud_asset_id=UUID(str(dto.cloud_asset_id)),
        policy_id=str(dto.policy_id),
        rule_id=str(dto.rule_id),
        severity=str(dto.severity),
        confidence=str(dto.confidence),
        title=str(dto.title),
        description=str(dto.description),
        status=str(dto.status),
        config_hash=str(dto.config_hash),
        fingerprint=str(dto.fingerprint),
        first_seen_at=dto.first_seen_at.isoformat(),
        last_seen_at=dto.last_seen_at.isoformat(),
        detected_at=dto.detected_at.isoformat(),
        resolved_at=dto.resolved_at.isoformat() if dto.resolved_at else None,
        reopened_at=dto.reopened_at.isoformat() if dto.reopened_at else None,
        suppressed_until=(
            dto.suppressed_until.isoformat() if dto.suppressed_until else None
        ),
        accepted_by=dto.accepted_by,
        accepted_reason=dto.accepted_reason,
        created_at=dto.created_at.isoformat(),
        updated_at=dto.updated_at.isoformat(),
        version=int(dto.version),
        compliance_mapping=[
            ComplianceRefResponse(
                framework_key=c.framework_key,
                requirement_ref=c.requirement_ref,
                resolved=c.resolved,
            )
            for c in dto.compliance_mapping
        ],
        evidence=[
            FindingEvidenceResponse(
                evidence_id=e.evidence_id,
                path=e.path,
                expected=e.expected,
                actual=e.actual,
                message=e.message,
            )
            for e in dto.evidence
        ],
        remediation=dict(dto.remediation or {}),
    )


def _policy_response(dto: Any) -> CSPMPolicyResponse:
    return CSPMPolicyResponse(
        policy_id=str(dto.policy_id),
        rule_id=str(dto.rule_id),
        title=str(dto.title),
        description=str(dto.description),
        severity=str(dto.severity),
        version=str(dto.version),
        provider_types=list(dto.provider_types),
        asset_types=list(dto.asset_types),
        enabled=bool(dto.enabled),
        evaluation_strategy=str(dto.evaluation_strategy),
        inherits_from=dto.inherits_from,
        metadata=dict(dto.metadata or {}),
        remediation=dict(dto.remediation or {}),
        compliance_mapping=[
            ComplianceRefResponse(
                framework_key=c.framework_key,
                requirement_ref=c.requirement_ref,
                resolved=c.resolved,
            )
            for c in dto.compliance_mapping
        ],
        rule=dict(dto.rule or {}),
        created_at=dto.created_at.isoformat(),
        updated_at=dto.updated_at.isoformat(),
    )


def _evaluation_response(dto: Any) -> CSPMEvaluationResponse:
    return CSPMEvaluationResponse(
        evaluation_id=UUID(str(dto.evaluation_id)),
        organization_id=str(dto.organization_id),
        cloud_account_id=dto.cloud_account_id,
        status=str(dto.status),
        assets_evaluated=int(dto.assets_evaluated),
        policies_evaluated=int(dto.policies_evaluated),
        findings_opened=int(dto.findings_opened),
        findings_resolved=int(dto.findings_resolved),
        diagnostics=dict(dto.diagnostics or {}),
        started_at=dto.started_at.isoformat(),
        completed_at=dto.completed_at.isoformat() if dto.completed_at else None,
        error_message=dto.error_message,
        results=[
            EvaluationResultResponse(
                policy_id=r.policy_id,
                rule_id=r.rule_id,
                cloud_asset_id=r.cloud_asset_id,
                passed=r.passed,
                severity=r.severity,
                title=r.title,
                message=r.message,
                duration_ms=r.duration_ms,
            )
            for r in dto.results
        ],
    )


@router.post(
    "/cspm/evaluations",
    status_code=status.HTTP_200_OK,
    response_model=CSPMEvaluationResponse,
)
async def trigger_cspm_evaluation(
    body: TriggerEvaluationRequest,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
    service: CSPMAssessmentService = Depends(get_cspm_assessment_service),
) -> CSPMEvaluationResponse:
    dto = await service.trigger_evaluation(
        TriggerCSPMEvaluationCommand(
            organization_id=tenant.organization_id,
            cloud_account_id=str(body.cloud_account_id) if body.cloud_account_id else None,
            triggered_by=tenant.user_id,
            policy_ids=tuple(body.policy_ids),
            incremental=body.incremental,
        )
    )
    return _evaluation_response(dto)


@router.post(
    "/cspm/assets/{asset_id}/evaluate",
    status_code=status.HTTP_200_OK,
    response_model=CSPMEvaluationResponse,
)
async def evaluate_cspm_asset(
    asset_id: UUID,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
    service: CSPMAssessmentService = Depends(get_cspm_assessment_service),
    policy_ids: list[str] | None = Query(default=None),
) -> CSPMEvaluationResponse:
    dto = await service.evaluate_asset(
        EvaluateAssetCommand(
            organization_id=tenant.organization_id,
            cloud_asset_id=str(asset_id),
            triggered_by=tenant.user_id,
            policy_ids=tuple(policy_ids or ()),
        )
    )
    return _evaluation_response(dto)


@router.get("/cspm/findings", response_model=CSPMFindingPageResponse)
async def list_cspm_findings(
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: CSPMAssessmentService = Depends(get_cspm_assessment_service),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=50, ge=1, le=200),
    status_filter: str | None = Query(default=None, alias="status"),
    cloud_asset_id: UUID | None = None,
    severity: str | None = None,
) -> CSPMFindingPageResponse:
    result = await service.list_findings(
        ListFindingsQuery(
            organization_id=tenant.organization_id,
            page=page,
            size=size,
            status=status_filter,
            cloud_asset_id=str(cloud_asset_id) if cloud_asset_id else None,
            severity=severity,
        )
    )
    return CSPMFindingPageResponse(
        items=[_finding_response(i) for i in result.items],
        page=result.page,
        size=result.size,
        total=result.total,
    )


@router.get("/cspm/findings/{finding_id}", response_model=CSPMFindingResponse)
async def get_cspm_finding(
    finding_id: UUID,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: CSPMAssessmentService = Depends(get_cspm_assessment_service),
) -> CSPMFindingResponse:
    dto = await service.get_finding(
        GetFindingQuery(
            organization_id=tenant.organization_id,
            finding_id=str(finding_id),
        )
    )
    return _finding_response(dto)


@router.patch(
    "/cspm/findings/{finding_id}/status",
    response_model=CSPMFindingResponse,
)
async def update_cspm_finding_status(
    finding_id: UUID,
    body: UpdateFindingStatusRequest,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
    service: CSPMAssessmentService = Depends(get_cspm_assessment_service),
) -> CSPMFindingResponse:
    dto = await service.update_finding_status(
        UpdateFindingStatusCommand(
            organization_id=tenant.organization_id,
            finding_id=str(finding_id),
            status=body.status,
            changed_by=tenant.user_id,
            reason=body.reason,
            suppressed_until=body.suppressed_until,
            accepted_by=body.accepted_by,
        )
    )
    return _finding_response(dto)


@router.get("/cspm/policies", response_model=list[CSPMPolicyResponse])
async def list_cspm_policies(
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: CSPMAssessmentService = Depends(get_cspm_assessment_service),
    enabled_only: bool = Query(default=False),
) -> list[CSPMPolicyResponse]:
    items = await service.list_policies(ListPoliciesQuery(enabled_only=enabled_only))
    return [_policy_response(i) for i in items]


@router.get("/cspm/policies/{policy_id}", response_model=CSPMPolicyResponse)
async def get_cspm_policy(
    policy_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: CSPMAssessmentService = Depends(get_cspm_assessment_service),
) -> CSPMPolicyResponse:
    dto = await service.get_policy(GetPolicyQuery(policy_id=policy_id))
    return _policy_response(dto)


@router.get("/cspm/evaluations", response_model=CSPMEvaluationPageResponse)
async def list_cspm_evaluations(
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: CSPMAssessmentService = Depends(get_cspm_assessment_service),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=50, ge=1, le=200),
) -> CSPMEvaluationPageResponse:
    result = await service.list_evaluations(
        ListEvaluationsQuery(
            organization_id=tenant.organization_id,
            page=page,
            size=size,
        )
    )
    return CSPMEvaluationPageResponse(
        items=[_evaluation_response(i) for i in result.items],
        page=result.page,
        size=result.size,
        total=result.total,
    )


@router.get("/cspm/evaluations/{evaluation_id}", response_model=CSPMEvaluationResponse)
async def get_cspm_evaluation(
    evaluation_id: UUID,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: CSPMAssessmentService = Depends(get_cspm_assessment_service),
) -> CSPMEvaluationResponse:
    dto = await service.get_evaluation(
        GetEvaluationQuery(
            organization_id=tenant.organization_id,
            evaluation_id=str(evaluation_id),
        )
    )
    return _evaluation_response(dto)


@router.get("/cspm/summary/findings", response_model=FindingSummaryResponse)
async def cspm_finding_summary(
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: CSPMAssessmentService = Depends(get_cspm_assessment_service),
) -> FindingSummaryResponse:
    dto = await service.finding_summary(SummaryQuery(organization_id=tenant.organization_id))
    return FindingSummaryResponse(
        organization_id=dto.organization_id,
        open_by_severity=dict(dto.open_by_severity),
        total_open=dto.total_open,
    )


@router.get("/cspm/summary/compliance", response_model=ComplianceSummaryResponse)
async def cspm_compliance_summary(
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: CSPMAssessmentService = Depends(get_cspm_assessment_service),
) -> ComplianceSummaryResponse:
    dto = await service.compliance_summary(
        SummaryQuery(organization_id=tenant.organization_id)
    )
    return ComplianceSummaryResponse(
        organization_id=dto.organization_id,
        mapped_frameworks=list(dto.mapped_frameworks),
        mapped_controls=dto.mapped_controls,
        unresolved_refs=dto.unresolved_refs,
        open_findings_with_mapping=dto.open_findings_with_mapping,
    )
