"""Domain ↔ ORM mapping for platform orchestration runs."""

from __future__ import annotations

from uuid import UUID, uuid4

from redforge.domain.cloud_security.platform.entities import (
    OrchestrationRun,
    OrchestrationStepResult,
)
from redforge.domain.cloud_security.platform.value_objects import (
    OrchestrationRunId,
    OrchestrationScope,
    RunStatus,
)
from redforge.domain.cloud_security.value_objects import OrganizationId
from redforge.infrastructure.database.models.cloud_security import (
    CloudOrchestrationRunModel,
    CloudPlatformValidationReportModel,
)


def run_to_model(
    run: OrchestrationRun, model: CloudOrchestrationRunModel | None = None
) -> CloudOrchestrationRunModel:
    target = model or CloudOrchestrationRunModel(id=run.id.value)
    target.id = run.id.value
    target.organization_id = str(run.organization_id)
    target.scope = run.scope.value
    target.target_id = run.target_id
    target.status = run.status.value
    target.steps = [step.to_dict() for step in run.steps]
    target.diagnostics = dict(run.diagnostics)
    target.operation_id = run.operation_id
    target.correlation_id = run.correlation_id
    target.request_id = run.request_id
    target.started_at = run.started_at
    target.completed_at = run.completed_at
    target.created_at = run.created_at
    target.updated_at = run.updated_at
    target.row_version = run.row_version
    return target


def run_from_model(model: CloudOrchestrationRunModel) -> OrchestrationRun:
    steps = [
        OrchestrationStepResult.from_dict(item)
        for item in (model.steps or [])
        if isinstance(item, dict)
    ]
    return OrchestrationRun(
        id=OrchestrationRunId(model.id),
        organization_id=OrganizationId(model.organization_id),
        scope=OrchestrationScope(model.scope),
        target_id=model.target_id,
        status=RunStatus(model.status),
        steps=steps,
        diagnostics=dict(model.diagnostics or {}),
        operation_id=model.operation_id,
        correlation_id=model.correlation_id or "",
        request_id=model.request_id or "",
        started_at=model.started_at,
        completed_at=model.completed_at,
        created_at=model.created_at,
        updated_at=model.updated_at,
        row_version=model.row_version,
    )


def validation_report_to_model(
    organization_id: str,
    report: dict[str, object],
    *,
    model: CloudPlatformValidationReportModel | None = None,
    report_id: UUID | None = None,
) -> CloudPlatformValidationReportModel:
    from datetime import UTC, datetime

    rid = report_id or uuid4()
    target = model or CloudPlatformValidationReportModel(id=rid)
    target.organization_id = organization_id
    target.report = dict(report)
    if model is None:
        target.created_at = datetime.now(UTC)
    return target
