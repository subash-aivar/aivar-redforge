
"""Domain exceptions for the evidence context."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from evidence.domain.value_objects.identifiers import TenantId


class DomainException(Exception):
    """Base for all evidence domain exceptions."""


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


class AggregateSealed(DomainException):
    def __init__(self, aggregate_id: str) -> None:
        super().__init__(f"Aggregate is sealed and immutable: {aggregate_id}")


class EvidenceNotFound(DomainException):
    def __init__(self, evidence_id: str) -> None:
        super().__init__(f"ExecutionEvidence not found: {evidence_id}")


class EvidenceChainNotFound(DomainException):
    def __init__(self, chain_id: str) -> None:
        super().__init__(f"EvidenceChain not found: {chain_id}")


class EvidenceIntegrityViolation(DomainException):
    def __init__(self, evidence_id: str, expected: str, computed: str) -> None:
        self.evidence_id = evidence_id
        self.expected = expected
        self.computed = computed
        super().__init__(
            f"Evidence integrity failed for {evidence_id}: "
            f"expected={expected} computed={computed}"
        )


class RetentionWindowActive(DomainException):
    def __init__(self, evidence_id: str, retention_class: str, expires_at: str) -> None:
        self.evidence_id = evidence_id
        self.retention_class = retention_class
        self.expires_at = expires_at
        super().__init__(
            f"Evidence {evidence_id} cannot be deleted until {expires_at} "
            f"(retention={retention_class})"
        )


class SealerRoleRequired(DomainException):
    def __init__(self, provided_role: str) -> None:
        self.provided_role = provided_role
        super().__init__(
            f"Evidence chain seal requires role 'evidence:sealer', got '{provided_role}'"
        )


class EvidenceQuarantinedError(DomainException):
    def __init__(self, evidence_id: str) -> None:
        super().__init__(f"Evidence is quarantined and content is inaccessible: {evidence_id}")
