"""Application-layer exception hierarchy for the operation context."""

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
