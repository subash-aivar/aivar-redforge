"""Domain exceptions for the operation bounded context."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from operation.domain.value_objects.identifiers import (
        ExecutionPlanVersionId,
        OperationId,
        TenantId,
    )


class DomainException(Exception):
    """Base for all operation domain exceptions."""


class InvalidArgument(DomainException):
    def __init__(self, field: str, reason: str) -> None:
        self.field = field
        self.reason = reason
        super().__init__(f"Invalid argument '{field}': {reason}")


class InvalidStateTransition(DomainException):
    def __init__(self, current: str, attempted: str, aggregate_id: str | None = None) -> None:
        self.current = current
        self.attempted = attempted
        self.aggregate_id = aggregate_id
        detail = f"Invalid state transition from {current} via {attempted}"
        if aggregate_id is not None:
            detail = f"{detail} (id={aggregate_id})"
        super().__init__(detail)


class TenantMismatch(DomainException):
    def __init__(self, expected: TenantId, actual: TenantId) -> None:
        self.expected = expected
        self.actual = actual
        super().__init__(f"Tenant mismatch: expected {expected}, got {actual}")


class OptimisticLockConflict(DomainException):
    def __init__(self, aggregate_id: str, expected: int, actual: int) -> None:
        self.aggregate_id = aggregate_id
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"Optimistic lock conflict for {aggregate_id}: "
            f"expected version {expected}, actual {actual}"
        )


class OperationNotFound(DomainException):
    def __init__(self, operation_id: OperationId, tenant_id: TenantId) -> None:
        self.operation_id = operation_id
        self.tenant_id = tenant_id
        super().__init__(f"Operation not found: {operation_id} for tenant {tenant_id}")


class ExecutionPlanVersionNotFound(DomainException):
    def __init__(
        self,
        plan_version_id: ExecutionPlanVersionId,
        tenant_id: TenantId,
    ) -> None:
        self.plan_version_id = plan_version_id
        self.tenant_id = tenant_id
        super().__init__(
            f"ExecutionPlanVersion not found: {plan_version_id} for tenant {tenant_id}"
        )


class CyclicDependencyError(DomainException):
    def __init__(self, from_step: str, to_step: str) -> None:
        self.from_step = from_step
        self.to_step = to_step
        super().__init__(
            f"Cyclic step dependency detected: {from_step} → {to_step}"
        )


class PlanValidationError(DomainException):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"Execution plan validation failed: {reason}")


class PlanImmutabilityViolation(DomainException):
    def __init__(self, plan_version_id: ExecutionPlanVersionId) -> None:
        self.plan_version_id = plan_version_id
        super().__init__(
            f"ExecutionPlanVersion is immutable after signing: {plan_version_id}"
        )


class ApprovalAuthorityInsufficient(DomainException):
    def __init__(self, required: str, provided: str) -> None:
        self.required = required
        self.provided = provided
        super().__init__(
            f"Insufficient approval authority: required {required}, provided {provided}"
        )


class EngagementNotActive(DomainException):
    def __init__(self, engagement_id: str, state: str) -> None:
        self.engagement_id = engagement_id
        self.state = state
        super().__init__(
            f"Engagement {engagement_id} is not Active (state={state})"
        )


class ConcurrentExecutingPlanError(DomainException):
    def __init__(self, operation_id: str) -> None:
        self.operation_id = operation_id
        super().__init__(
            f"Only one ExecutionPlanVersion may be Executing for operation {operation_id}"
        )
