"""Application-layer errors for siem_ingestion's Event Ingestion Pipeline.

These are the domain errors the validation pipeline (M42 Phase 3, §3 of
this milestone) returns — never a bare `ValueError`/`AssertionError` —
so a `ValidationFailed`/`Rejected` acceptance result can carry typed,
inspectable failures rather than opaque strings.
"""

from __future__ import annotations


class ApplicationError(Exception):
    pass


class ApplicationForbiddenError(ApplicationError):
    def __init__(self, required_role: str) -> None:
        super().__init__(f"Requires role {required_role}")
        self.required_role = required_role


class ApplicationValidationError(ApplicationError):
    """Base type for every validation-pipeline stage failure."""


class MissingRequiredFieldError(ApplicationValidationError):
    def __init__(self, field_name: str) -> None:
        super().__init__(f"Missing required field: {field_name}")
        self.field_name = field_name


class TenantContextMismatchError(ApplicationValidationError):
    def __init__(self, expected: object, actual: object) -> None:
        super().__init__(f"Tenant context mismatch: expected {expected}, got {actual}")


class TimestampOutOfSanityRangeError(ApplicationValidationError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"occurred_at failed timestamp sanity check: {reason}")


class InvalidEventCategoryError(ApplicationValidationError):
    def __init__(self, raw: str) -> None:
        super().__init__(f"Unknown event category: {raw!r}")
        self.raw = raw


class InvalidEventOutcomeError(ApplicationValidationError):
    def __init__(self, raw: str) -> None:
        super().__init__(f"Unknown event outcome: {raw!r}")
        self.raw = raw


class InvalidEventSeverityError(ApplicationValidationError):
    def __init__(self, raw: str) -> None:
        super().__init__(f"Unknown event severity: {raw!r}")
        self.raw = raw


class PayloadTooLargeError(ApplicationValidationError):
    def __init__(self, size_bytes: int, limit_bytes: int) -> None:
        super().__init__(
            f"Payload attributes size {size_bytes} bytes exceeds limit {limit_bytes} bytes"
        )
        self.size_bytes = size_bytes
        self.limit_bytes = limit_bytes


class SchemaVersionUnsupportedError(ApplicationValidationError):
    def __init__(self, requested: object, supported: object) -> None:
        super().__init__(f"Schema version {requested} is incompatible with supported {supported}")
        self.requested = requested
        self.supported = supported


class EmptyBatchSubmissionError(ApplicationValidationError):
    def __init__(self) -> None:
        super().__init__("SubmitBatchCommand.events must contain at least one event command")
