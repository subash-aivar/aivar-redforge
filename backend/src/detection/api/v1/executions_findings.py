"""Detection execution and finding API routers."""

from __future__ import annotations

from dataclasses import asdict
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response, status

from detection.api.dependencies import (
    ExecutionFindingServiceDep,
    PrincipalIdDep,
    TenantIdDep,
)
from detection.api.schemas.execution_finding_schemas import (
    ConfirmFindingRequest,
    DetectionExecutionResponse,
    DetectionFindingResponse,
    EscalateFindingRequest,
    FalsePositiveRequest,
    ListExecutionsResponse,
    ListFindingsResponse,
    RecordExecutionResultRequest,
    ScheduleExecutionRequest,
    SuppressFindingRequest,
    TriageFindingRequest,
)
from detection.application.commands.execution_finding_commands import (
    ConfirmFinding,
    EscalateFindingToInvestigation,
    MarkFindingFalsePositive,
    RecordExecutionResult,
    ScheduleRuleExecution,
    SuppressFinding,
    TriageFinding,
)
from detection.application.dtos.execution_finding_dtos import (
    DetectionExecutionDTO,
    DetectionFindingDTO,
)
from detection.application.queries.execution_finding_queries import (
    GetExecution,
    GetFinding,
    ListExecutions,
    ListFindings,
)
from redforge.api.security import TenantContext, require_permission
from redforge.domain.identity.value_objects import Permission

executions_router = APIRouter()
findings_router = APIRouter()


def _execution_response(dto: DetectionExecutionDTO) -> DetectionExecutionResponse:
    return DetectionExecutionResponse.model_validate(asdict(dto))


def _finding_response(dto: DetectionFindingDTO) -> DetectionFindingResponse:
    return DetectionFindingResponse.model_validate(asdict(dto))


@executions_router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=DetectionExecutionResponse,
)
async def schedule_execution(
    body: ScheduleExecutionRequest,
    response: Response,
    tenant_id: TenantIdDep,
    svc: ExecutionFindingServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
) -> DetectionExecutionResponse:
    dto = await svc.schedule_rule_execution(
        ScheduleRuleExecution(
            tenant_id=tenant_id,
            rule_id=UUID(body.rule_id),
            source_id=body.source_id,
            window_start=body.window_start,
            window_end=body.window_end,
            trigger=body.trigger,
            rule_version=body.rule_version,
            source_type=body.source_type,
        )
    )
    response.headers["Location"] = f"/api/v1/detection-executions/{dto.id}"
    return _execution_response(dto)


@executions_router.get("", response_model=ListExecutionsResponse)
async def list_executions(
    tenant_id: TenantIdDep,
    svc: ExecutionFindingServiceDep,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    state: str | None = Query(default=None),
    _tenant: TenantContext = Depends(require_permission(Permission.FINDINGS_READ)),
) -> ListExecutionsResponse:
    page = await svc.list_executions(
        ListExecutions(
            tenant_id=tenant_id, limit=limit, offset=offset, state=state
        )
    )
    return ListExecutionsResponse(
        items=[_execution_response(i) for i in page.items],
        limit=page.limit,
        offset=page.offset,
    )


@executions_router.get("/{execution_id}", response_model=DetectionExecutionResponse)
async def get_execution(
    execution_id: UUID,
    tenant_id: TenantIdDep,
    svc: ExecutionFindingServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.FINDINGS_READ)),
) -> DetectionExecutionResponse:
    dto = await svc.get_execution(
        GetExecution(tenant_id=tenant_id, execution_id=execution_id)
    )
    return _execution_response(dto)


@executions_router.post(
    "/{execution_id}/result",
    response_model=DetectionExecutionResponse,
)
async def record_execution_result(
    execution_id: UUID,
    body: RecordExecutionResultRequest,
    tenant_id: TenantIdDep,
    svc: ExecutionFindingServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
) -> DetectionExecutionResponse:
    dto = await svc.record_execution_result(
        RecordExecutionResult(
            tenant_id=tenant_id,
            execution_id=execution_id,
            telemetry_records_evaluated=body.telemetry_records_evaluated,
            findings_produced=body.findings_produced,
            duration_ms=body.duration_ms,
            cpu_ms=body.cpu_ms,
            finding_ids=[UUID(x) for x in body.finding_ids],
            failed=body.failed,
            timed_out=body.timed_out,
            error_type=body.error_type,
            error_message=body.error_message,
        )
    )
    return _execution_response(dto)


@findings_router.get("", response_model=ListFindingsResponse)
async def list_findings(
    tenant_id: TenantIdDep,
    svc: ExecutionFindingServiceDep,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    open_only: bool = Query(default=False),
    asset_id: str | None = Query(default=None),
    _tenant: TenantContext = Depends(require_permission(Permission.FINDINGS_READ)),
) -> ListFindingsResponse:
    page = await svc.list_findings(
        ListFindings(
            tenant_id=tenant_id,
            limit=limit,
            offset=offset,
            open_only=open_only,
            asset_id=asset_id,
        )
    )
    return ListFindingsResponse(
        items=[_finding_response(i) for i in page.items],
        limit=page.limit,
        offset=page.offset,
    )


@findings_router.get("/{finding_id}", response_model=DetectionFindingResponse)
async def get_finding(
    finding_id: UUID,
    tenant_id: TenantIdDep,
    svc: ExecutionFindingServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.FINDINGS_READ)),
) -> DetectionFindingResponse:
    dto = await svc.get_finding(
        GetFinding(tenant_id=tenant_id, finding_id=finding_id)
    )
    return _finding_response(dto)


@findings_router.post("/{finding_id}/triage", response_model=DetectionFindingResponse)
async def triage_finding(
    finding_id: UUID,
    body: TriageFindingRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: ExecutionFindingServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
) -> DetectionFindingResponse:
    dto = await svc.triage_finding(
        TriageFinding(
            tenant_id=tenant_id,
            finding_id=finding_id,
            analyst=str(principal_id),
            note=body.note,
        )
    )
    return _finding_response(dto)


@findings_router.post("/{finding_id}/confirm", response_model=DetectionFindingResponse)
async def confirm_finding(
    finding_id: UUID,
    body: ConfirmFindingRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: ExecutionFindingServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
) -> DetectionFindingResponse:
    _ = body
    dto = await svc.confirm_finding(
        ConfirmFinding(
            tenant_id=tenant_id,
            finding_id=finding_id,
            analyst=str(principal_id),
        )
    )
    return _finding_response(dto)


@findings_router.post(
    "/{finding_id}/false-positive",
    response_model=DetectionFindingResponse,
)
async def mark_false_positive(
    finding_id: UUID,
    body: FalsePositiveRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: ExecutionFindingServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
) -> DetectionFindingResponse:
    dto = await svc.mark_finding_false_positive(
        MarkFindingFalsePositive(
            tenant_id=tenant_id,
            finding_id=finding_id,
            analyst=str(principal_id),
            justification=body.justification,
        )
    )
    return _finding_response(dto)


@findings_router.post("/{finding_id}/suppress", response_model=DetectionFindingResponse)
async def suppress_finding(
    finding_id: UUID,
    body: SuppressFindingRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: ExecutionFindingServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
) -> DetectionFindingResponse:
    dto = await svc.suppress_finding(
        SuppressFinding(
            tenant_id=tenant_id,
            finding_id=finding_id,
            analyst=str(principal_id),
            justification=body.justification,
        )
    )
    return _finding_response(dto)


@findings_router.post("/{finding_id}/escalate", response_model=DetectionFindingResponse)
async def escalate_finding(
    finding_id: UUID,
    body: EscalateFindingRequest,
    tenant_id: TenantIdDep,
    principal_id: PrincipalIdDep,
    svc: ExecutionFindingServiceDep,
    _tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
) -> DetectionFindingResponse:
    dto = await svc.escalate_finding_to_investigation(
        EscalateFindingToInvestigation(
            tenant_id=tenant_id,
            finding_id=finding_id,
            analyst=str(principal_id),
            investigation_id=body.investigation_id,
        )
    )
    return _finding_response(dto)
