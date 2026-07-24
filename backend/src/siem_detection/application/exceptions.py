"""Application-layer errors for siem_detection's Detection Engine
(M42 Phase 6 / M44A).

Validation and evaluator-selection failures are always one of these
typed errors — never a bare `ValueError`/`KeyError` — so a detection
result can carry an inspectable failure rather than an opaque string.
"""

from __future__ import annotations


class ApplicationError(Exception):
    pass


class ApplicationForbiddenError(ApplicationError):
    def __init__(self, required_role: str) -> None:
        super().__init__(f"Requires role {required_role}")
        self.required_role = required_role


class ApplicationValidationError(ApplicationError):
    """Base type for every pre-evaluation request-shape validation failure."""


class MissingRequiredFieldError(ApplicationValidationError):
    def __init__(self, field_name: str) -> None:
        super().__init__(f"Missing required field: {field_name}")
        self.field_name = field_name


class EmptyBatchEvaluationError(ApplicationValidationError):
    def __init__(self) -> None:
        super().__init__("EvaluateBatchCommand.events must contain at least one CanonicalEvent")


class TenantContextMismatchError(ApplicationValidationError):
    def __init__(self, expected: object, actual: object) -> None:
        super().__init__(f"Tenant context mismatch: expected {expected}, got {actual}")


class InvalidDetectionMatchError(ApplicationValidationError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Invalid DetectionMatch: {reason}")


class EvaluatorSelectionError(ApplicationError):
    """Base type for every evaluator-selection-strategy failure."""


class UnsupportedEvaluatorError(EvaluatorSelectionError):
    def __init__(self, rule_id: str) -> None:
        super().__init__(f"No evaluator registered for rule {rule_id!r}")
        self.rule_id = rule_id


class UnsupportedEvaluatorVersionError(EvaluatorSelectionError):
    def __init__(self, rule_id: str, requested: object) -> None:
        super().__init__(
            f"No evaluator registered for rule {rule_id!r} compatible with "
            f"schema version {requested}"
        )
        self.rule_id = rule_id
        self.requested = requested


class AmbiguousEvaluatorSelectionError(EvaluatorSelectionError):
    def __init__(
        self, rule_id: str, requested: object, candidate_versions: tuple[object, ...]
    ) -> None:
        super().__init__(
            f"{len(candidate_versions)} evaluators registered for rule {rule_id!r} are all "
            f"compatible with requested schema version {requested}: {candidate_versions} — "
            "selection is ambiguous"
        )
        self.rule_id = rule_id
        self.requested = requested
        self.candidate_versions = candidate_versions


class DuplicateEvaluatorRegistrationError(ApplicationError):
    def __init__(self, rule_id: str, schema_version: object) -> None:
        super().__init__(
            f"An evaluator for rule {rule_id!r} at schema version {schema_version} "
            "is already registered"
        )
        self.rule_id = rule_id
        self.schema_version = schema_version
