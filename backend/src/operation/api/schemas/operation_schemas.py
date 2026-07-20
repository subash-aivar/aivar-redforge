"""Pydantic schemas for operation API."""

from __future__ import annotations

from pydantic import BaseModel, Field


class CreateOperationRequest(BaseModel):
    engagement_id: str
    name: str = Field(min_length=1, max_length=256)
    classification: str


class AddExecutionStepRequest(BaseModel):
    name: str = Field(min_length=1, max_length=256)
    step_type: str
    max_duration_seconds: int = Field(gt=0)
    rollback_on_failure: bool = True
    continue_on_failure: bool = False
    technique_payload_id: str | None = None
    technique_id: str | None = None
    target_asset_id: str | None = None
    impact_ceiling: str | None = None
    modifies_persistent_state: bool = False
    mitre_technique_id: str | None = None
    mitre_tactic: str | None = None
    rate_limit_max: int | None = None
    rate_limit_window_seconds: int | None = None
    window_allowed_days: list[int] | None = None
    window_start_hour: int | None = None
    window_end_hour: int | None = None
    description: str = ""


class AddStepDependencyRequest(BaseModel):
    from_step_id: str
    to_step_id: str


class ObjectiveItem(BaseModel):
    description: str
    success_criteria: str
    is_primary: bool = False


class SetObjectivesRequest(BaseModel):
    objectives: list[ObjectiveItem]


class SignExecutionPlanRequest(BaseModel):
    signature: str = Field(min_length=1, max_length=4096)


class ApproveOperationRequest(BaseModel):
    authority: str = Field(min_length=1, max_length=64)
    signature: str = Field(min_length=1, max_length=4096)


class ExecutionStepResponse(BaseModel):
    id: str
    name: str
    step_type: str
    state: str
    impact_ceiling: str | None
    modifies_persistent_state: bool
    technique_id: str | None
    target_asset_id: str | None


class StepDependencyResponse(BaseModel):
    id: str
    from_step_id: str
    to_step_id: str


class OperationApprovalResponse(BaseModel):
    id: str
    operator_id: str
    authority: str
    approved_at: str


class OperationObjectiveResponse(BaseModel):
    id: str
    description: str
    success_criteria: str
    is_primary: bool


class OperationResponse(BaseModel):
    id: str
    tenant_id: str
    engagement_id: str
    name: str
    classification: str
    state: str
    risk: str
    steps: list[ExecutionStepResponse]
    dependencies: list[StepDependencyResponse]
    approvals: list[OperationApprovalResponse]
    objectives: list[OperationObjectiveResponse]
    abort_reason: str | None
    created_at: str
    updated_at: str
    version: int


class ListOperationsResponse(BaseModel):
    items: list[OperationResponse]
    count: int


class PlanValidationResponse(BaseModel):
    operation_id: str
    valid: bool
    message: str


class ExecutionPlanVersionResponse(BaseModel):
    id: str
    tenant_id: str
    operation_id: str
    version_number: int
    state: str
    plan_hash: str | None
    signed_by_operator_id: str | None
    signed_at: str | None
    created_at: str
    updated_at: str
    version: int


class ListPlanVersionsResponse(BaseModel):
    items: list[ExecutionPlanVersionResponse]
    count: int
