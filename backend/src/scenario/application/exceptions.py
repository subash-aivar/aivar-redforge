"""Application-layer exceptions for scenario context."""

from __future__ import annotations


class ApplicationError(Exception):
    """Base application error."""


class ApplicationNotFoundError(ApplicationError):
    def __init__(self, resource: str, resource_id: str) -> None:
        super().__init__(f"{resource} not found: {resource_id}")
        self.resource = resource
        self.resource_id = resource_id


class ApplicationValidationError(ApplicationError):
    def __init__(self, message: str) -> None:
        super().__init__(message)
