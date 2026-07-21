"""Domain exceptions for exposure."""

from __future__ import annotations


class ExposureDomainError(Exception):
    """Base domain error."""


class TenantContextMissingError(ExposureDomainError):
    def __init__(self) -> None:
        super().__init__("TenantId is required for all exposure repository operations")


class TenantMismatch(ExposureDomainError):
    def __init__(self, expected: object, actual: object) -> None:
        super().__init__(f"Tenant mismatch: expected {expected}, got {actual}")


class InvalidExposureTransition(ExposureDomainError):
    def __init__(self, from_state: str, to_state: str) -> None:
        super().__init__(f"Invalid exposure transition {from_state} → {to_state}")


class SuppressionJustificationRequired(ExposureDomainError):
    def __init__(self) -> None:
        super().__init__("suppression_justification must be a non-empty string")


class ResolvedAtImmutable(ExposureDomainError):
    def __init__(self) -> None:
        super().__init__("resolved_at is immutable once set")


class ChangeRationaleRequired(ExposureDomainError):
    def __init__(self) -> None:
        super().__init__("change_rationale must be a non-empty string")


class OptimisticConcurrencyConflict(ExposureDomainError):
    def __init__(self, record_id: str) -> None:
        super().__init__(f"Optimistic concurrency conflict on ExposureRecord {record_id}")


class ExposureRecordConflict(ExposureDomainError):
    """Second CAS failure — route to DLQ."""

    def __init__(self, record_id: str) -> None:
        super().__init__(f"ExposureRecordConflict after retry: {record_id}")
