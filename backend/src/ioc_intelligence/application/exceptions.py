"""Application-level exceptions for ioc_intelligence (M51.2 Phase A2),
mirroring `threat_actor_intel.application.exceptions`'s established
shape."""

from __future__ import annotations


class ApplicationError(Exception):
    pass


class ApplicationForbiddenError(ApplicationError):
    def __init__(self, required_role: str) -> None:
        super().__init__(f"Requires role {required_role}")
        self.required_role = required_role


class ApplicationNotFoundError(ApplicationError):
    def __init__(self, entity: str, key: str) -> None:
        super().__init__(f"{entity} not found: {key}")


class ApplicationValidationError(ApplicationError):
    pass
