"""campaignexecution application exceptions."""

from __future__ import annotations


class ApplicationError(Exception):
    """Base class for application-layer exceptions."""


class ApplicationNotFoundError(ApplicationError):
    def __init__(self, entity: str, entity_id: str) -> None:
        super().__init__(f"{entity} not found: {entity_id}")
        self.entity = entity
        self.entity_id = entity_id


class ApplicationValidationError(ApplicationError):
    def __init__(self, field: str, message: str) -> None:
        super().__init__(f"Validation error on '{field}': {message}")
        self.field = field
        self.message = message


class ApplicationConflictError(ApplicationError):
    def __init__(self, message: str) -> None:
        super().__init__(message)
