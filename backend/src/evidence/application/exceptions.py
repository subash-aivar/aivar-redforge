
"""Application-layer exception hierarchy for the evidence context."""

from __future__ import annotations


class ApplicationException(Exception):  # noqa: N818
    """Base for all application-layer exceptions."""


class ApplicationValidationError(ApplicationException):
    def __init__(self, field: str, reason: str) -> None:
        self.field = field
        self.reason = reason
        super().__init__(f"Invalid {field}: {reason}")


class ApplicationNotFoundError(ApplicationException):
    def __init__(self, resource: str, resource_id: str) -> None:
        self.resource = resource
        self.resource_id = resource_id
        super().__init__(f"{resource} not found: {resource_id}")


class ApplicationConflictError(ApplicationException):
    def __init__(self, message: str) -> None:
        super().__init__(message)


class ApplicationAuthorizationError(ApplicationException):
    def __init__(self, message: str, check: str | None = None) -> None:
        self.check = check
        super().__init__(message)


class ApplicationIntegrityError(ApplicationException):
    """Raised when evidence integrity fails — never includes tampered content."""

    def __init__(self, evidence_id: str, expected_hash: str, computed_hash: str) -> None:
        self.evidence_id = evidence_id
        self.expected_hash = expected_hash
        self.computed_hash = computed_hash
        super().__init__(
            f"Evidence integrity failed for {evidence_id} "
            f"(expected={expected_hash}, computed={computed_hash})"
        )
