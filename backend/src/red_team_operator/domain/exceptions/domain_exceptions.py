"""Domain exceptions for the operator bounded context."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from red_team_operator.domain.value_objects.identifiers import OperatorId, TenantId


class DomainException(Exception):
    """Base for all operator domain exceptions."""


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


class OperatorNotFound(DomainException):
    def __init__(self, operator_id: OperatorId, tenant_id: TenantId | None = None) -> None:
        self.operator_id = operator_id
        self.tenant_id = tenant_id
        detail = f"RedTeamOperator not found: {operator_id}"
        if tenant_id is not None:
            detail = f"{detail} for tenant {tenant_id}"
        super().__init__(detail)


class OperatorNotAuthorized(DomainException):
    """Raised when a suspended/revoked/insufficient-clearance operator attempts an action."""

    def __init__(self, reason: str, operator_id: str | None = None) -> None:
        self.reason = reason
        self.operator_id = operator_id
        detail = reason if operator_id is None else f"{reason} (operator={operator_id})"
        super().__init__(detail)
