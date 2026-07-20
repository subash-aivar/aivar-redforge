"""Domain exceptions for M26 Phase 8 platform orchestration."""

from __future__ import annotations

from redforge.core.exceptions import NotFoundError, ValidationError


class InvalidPlatformArgumentError(ValidationError):
    def __init__(self, field: str, message: str) -> None:
        self.field = field
        super().__init__(message=f"{field}: {message}", details={field: message})


class OrchestrationRunNotFoundError(NotFoundError):
    def __init__(self, run_id: str) -> None:
        super().__init__(resource="OrchestrationRun", identifier=run_id)
        self.run_id = run_id


class PlatformOrchestrationError(ValidationError):
    def __init__(self, message: str, *, details: dict[str, str] | None = None) -> None:
        super().__init__(message=message, details=details or {})
