"""Application-level exceptions for attack_pattern_intel (M51.3 Phase
B1), mirroring `ioc_intelligence.application.exceptions`'s established
shape."""

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
