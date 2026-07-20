"""Domain exceptions for the engagement bounded context."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from engagement.domain.value_objects.identifiers import (
        EngagementId,
        TargetAuthorizationId,
        TenantId,
    )


class DomainException(Exception):
    """Base for all engagement domain exceptions."""


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


class EngagementNotFound(DomainException):
    def __init__(self, engagement_id: EngagementId, tenant_id: TenantId) -> None:
        self.engagement_id = engagement_id
        self.tenant_id = tenant_id
        super().__init__(
            f"Engagement not found: {engagement_id} for tenant {tenant_id}"
        )


class TargetAuthorizationNotFound(DomainException):
    def __init__(
        self,
        authorization_id: TargetAuthorizationId,
        tenant_id: TenantId,
    ) -> None:
        self.authorization_id = authorization_id
        self.tenant_id = tenant_id
        super().__init__(
            f"TargetAuthorization not found: {authorization_id} for tenant {tenant_id}"
        )


class DuplicateApproval(DomainException):
    def __init__(self, approver_id: str, engagement_id: str) -> None:
        self.approver_id = approver_id
        self.engagement_id = engagement_id
        super().__init__(
            f"Duplicate approval from {approver_id} for engagement {engagement_id}"
        )


class QuorumNotMet(DomainException):
    def __init__(self, required: int, actual: int, engagement_id: str) -> None:
        self.required = required
        self.actual = actual
        self.engagement_id = engagement_id
        super().__init__(
            f"Approval quorum not met for {engagement_id}: "
            f"required {required}, have {actual}"
        )


class ScopeImmutableViolation(DomainException):
    def __init__(self, engagement_id: str) -> None:
        self.engagement_id = engagement_id
        super().__init__(
            f"TargetScope is immutable for engagement {engagement_id}; "
            "use request_scope_expansion"
        )


class ArchivedImmutabilityViolation(DomainException):
    def __init__(self, engagement_id: str) -> None:
        self.engagement_id = engagement_id
        super().__init__(f"Archived engagement is immutable: {engagement_id}")


class AuthorizationReinstatementForbidden(DomainException):
    def __init__(self, authorization_id: str) -> None:
        self.authorization_id = authorization_id
        super().__init__(
            f"Revoked TargetAuthorization cannot be reinstated: {authorization_id}; "
            "create a new authorization"
        )
