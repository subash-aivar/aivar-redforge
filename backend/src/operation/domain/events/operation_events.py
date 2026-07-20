"""Domain events for the Operation aggregate."""

from __future__ import annotations

from dataclasses import dataclass

from operation.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class OperationCreated(BaseDomainEvent):
    engagement_id: str
    classification: str
    name: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ExecutionPlanDrafted(BaseDomainEvent):
    step_count: int


@dataclass(frozen=True, slots=True, kw_only=True)
class ExecutionStepAdded(BaseDomainEvent):
    step_id: str
    step_type: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ExecutionStepRemoved(BaseDomainEvent):
    step_id: str


@dataclass(frozen=True, slots=True, kw_only=True)
class OperationSubmittedForApproval(BaseDomainEvent):
    risk: str


@dataclass(frozen=True, slots=True, kw_only=True)
class OperationApproved(BaseDomainEvent):
    approval_id: str
    authority: str
    operator_id: str
    approval_count: int


@dataclass(frozen=True, slots=True, kw_only=True)
class OperationQueued(BaseDomainEvent):
    engagement_id: str


@dataclass(frozen=True, slots=True, kw_only=True)
class OperationStarted(BaseDomainEvent):
    engagement_id: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ExecutionStepStarted(BaseDomainEvent):
    step_id: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ExecutionStepCompleted(BaseDomainEvent):
    step_id: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ExecutionStepFailed(BaseDomainEvent):
    step_id: str
    reason: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ExecutionStepAborted(BaseDomainEvent):
    step_id: str
    reason: str


@dataclass(frozen=True, slots=True, kw_only=True)
class HumanApprovalGateReached(BaseDomainEvent):
    step_id: str


@dataclass(frozen=True, slots=True, kw_only=True)
class HumanApprovalGranted(BaseDomainEvent):
    step_id: str
    operator_id: str


@dataclass(frozen=True, slots=True, kw_only=True)
class HumanApprovalDenied(BaseDomainEvent):
    step_id: str
    operator_id: str
    reason: str


@dataclass(frozen=True, slots=True, kw_only=True)
class OperationPaused(BaseDomainEvent):
    reason: str | None


@dataclass(frozen=True, slots=True, kw_only=True)
class OperationResumed(BaseDomainEvent):
    pass


@dataclass(frozen=True, slots=True, kw_only=True)
class OperationCompleted(BaseDomainEvent):
    pass


@dataclass(frozen=True, slots=True, kw_only=True)
class OperationAborted(BaseDomainEvent):
    reason: str
    aborting_authority: str


@dataclass(frozen=True, slots=True, kw_only=True)
class OperationFailed(BaseDomainEvent):
    reason: str


@dataclass(frozen=True, slots=True, kw_only=True)
class RollbackInitiated(BaseDomainEvent):
    reason: str


@dataclass(frozen=True, slots=True, kw_only=True)
class RollbackCompleted(BaseDomainEvent):
    success: bool
