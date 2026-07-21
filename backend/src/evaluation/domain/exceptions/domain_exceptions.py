"""Evaluation bounded context domain exceptions.

Exception names follow DDD ubiquitous-language naming from the architecture spec.
"""

# ruff: noqa: N818
from __future__ import annotations


class EvaluationDomainException(Exception):
    """Base class for all evaluation domain exceptions."""


class EvaluationAlreadyComplete(EvaluationDomainException):
    def __init__(self, evaluation_id: str) -> None:
        super().__init__(f"Evaluation '{evaluation_id}' is already complete — sealed")
        self.evaluation_id = evaluation_id


class InvalidEvaluationState(EvaluationDomainException):
    def __init__(self, current: str, operation: str) -> None:
        super().__init__(f"Cannot perform '{operation}' when evaluation is in state '{current}'")
        self.current = current
        self.operation = operation


class ObjectiveAlreadyAssessed(EvaluationDomainException):
    def __init__(self, objective_id: str) -> None:
        super().__init__(
            f"Objective '{objective_id}' has already been assessed — idempotency guard"
        )
        self.objective_id = objective_id


class NoObjectivesRegistered(EvaluationDomainException):
    def __init__(self, evaluation_id: str) -> None:
        super().__init__(
            f"Evaluation '{evaluation_id}' has no objective assessments — cannot complete"
        )


class TenantMismatch(EvaluationDomainException):
    def __init__(self, expected: object, actual: object) -> None:
        super().__init__(f"Tenant mismatch: expected {expected}, got {actual}")


class MetricsSnapshotSealed(EvaluationDomainException):
    def __init__(self, snapshot_id: str) -> None:
        super().__init__(f"MetricsSnapshot '{snapshot_id}' is immutable once created")
