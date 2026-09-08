"""Application-level exceptions for threat_report_intel, mirroring
`infrastructure_intel.application.exceptions`'s established shape."""

from __future__ import annotations


class ApplicationError(Exception):
    pass


class ApplicationForbiddenError(ApplicationError):
    def __init__(self, required_permission: str) -> None:
        super().__init__(f"Requires permission {required_permission}")
        self.required_permission = required_permission


class ApplicationNotFoundError(ApplicationError):
    def __init__(self, entity: str, key: str) -> None:
        super().__init__(f"{entity} not found: {key}")


class ApplicationValidationError(ApplicationError):
    pass
