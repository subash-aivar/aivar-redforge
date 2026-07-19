"""Application-layer exception hierarchy for the Credential Vault."""

from __future__ import annotations


class ApplicationException(Exception):  # noqa: N818
    """Base for all application-layer exceptions."""


class ApplicationAuditFailure(ApplicationException):
    """Raised when AuditEntry persistence fails. Causes transaction rollback."""

    def __init__(self, message: str) -> None:
        super().__init__(message)


class ApplicationPortError(ApplicationException):
    """Raised when an external port call (KMS, permissions) fails unexpectedly."""

    def __init__(self, port_name: str, cause: Exception) -> None:
        self.port_name = port_name
        self.cause = cause
        super().__init__(f"{port_name} port failure: {cause}")


class ApplicationValidationError(ApplicationException):
    """Raised when command/query field validation fails before UoW opens."""

    def __init__(self, field: str, reason: str) -> None:
        self.field = field
        self.reason = reason
        super().__init__(f"Invalid {field}: {reason}")
