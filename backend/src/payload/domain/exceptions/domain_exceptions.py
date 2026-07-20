"""Domain exceptions for the payload context."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from payload.domain.value_objects.identifiers import TenantId


class DomainException(Exception):
    """Base for all payload domain exceptions."""


class InvalidArgument(DomainException):
    def __init__(self, message: str) -> None:
        super().__init__(message)


class InvalidStateTransition(DomainException):
    def __init__(self, from_state: str, to_state: str, aggregate_id: str) -> None:
        self.from_state = from_state
        self.to_state = to_state
        self.aggregate_id = aggregate_id
        super().__init__(
            f"Invalid transition {from_state} → {to_state} for {aggregate_id}"
        )


class TenantMismatch(DomainException):
    def __init__(self, expected: TenantId, actual: TenantId) -> None:
        self.expected = expected
        self.actual = actual
        super().__init__(f"Tenant mismatch: expected {expected}, got {actual}")


class OptimisticLockConflict(DomainException):
    def __init__(self, aggregate_type: str, aggregate_id: str) -> None:
        super().__init__(f"Optimistic lock conflict on {aggregate_type} {aggregate_id}")


class PayloadNotFound(DomainException):
    def __init__(self, payload_id: str) -> None:
        super().__init__(f"Payload not found: {payload_id}")


class PluginNotFound(DomainException):
    def __init__(self, plugin_id: str) -> None:
        super().__init__(f"PluginRegistration not found: {plugin_id}")


class CisoApprovalRequired(DomainException):
    def __init__(self, payload_id: str) -> None:
        super().__init__(
            f"Destruct-impact payload {payload_id} requires ciso_approved=True"
        )


class PayloadHashMismatch(DomainException):
    def __init__(self, payload_id: str, expected: str, computed: str) -> None:
        self.payload_id = payload_id
        self.expected = expected
        self.computed = computed
        super().__init__(
            f"Payload hash mismatch for {payload_id}: "
            f"expected={expected} computed={computed}"
        )


class PayloadNotApproved(DomainException):
    def __init__(self, payload_id: str, state: str) -> None:
        super().__init__(f"Payload {payload_id} is not approved (state={state})")


class PayloadRevokedError(DomainException):
    def __init__(self, payload_id: str) -> None:
        super().__init__(f"Payload {payload_id} is revoked")
