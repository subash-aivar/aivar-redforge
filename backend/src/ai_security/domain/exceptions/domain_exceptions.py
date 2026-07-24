"""Domain exceptions for ai_security (M47A).

Independent of `cloud_security`, `vulnerability_engine`, and `siem_*`
exception hierarchies — ai_security is its own bounded context and
must not import domain objects from any of them."""

from __future__ import annotations


class AiSecurityDomainError(Exception):
    """Base domain error for ai_security."""


class TenantMismatch(AiSecurityDomainError):
    def __init__(self, expected: object, actual: object) -> None:
        super().__init__(f"Tenant mismatch: expected {expected}, got {actual}")


class EmptyIdentifierError(AiSecurityDomainError):
    def __init__(self, identifier_name: str) -> None:
        super().__init__(f"{identifier_name} must be a non-empty string")


class EmptyDisplayNameError(AiSecurityDomainError):
    def __init__(self) -> None:
        super().__init__("name must be a non-empty string")


class InvalidEndpointUrlError(AiSecurityDomainError):
    def __init__(self, value: str) -> None:
        super().__init__(
            f"Invalid EndpointUrl, expected a non-empty http(s):// string, got {value!r}"
        )


class InvalidModelVersionError(AiSecurityDomainError):
    def __init__(self) -> None:
        super().__init__("ModelVersion.value must be a non-empty string")


class InvalidContextWindowError(AiSecurityDomainError):
    def __init__(self, value: int) -> None:
        super().__init__(f"ContextWindow must be a positive integer, got {value}")


class InvalidTemperatureError(AiSecurityDomainError):
    def __init__(self, value: float) -> None:
        super().__init__(f"Temperature must be between 0.0 and 2.0, got {value}")


class InvalidTokenLimitError(AiSecurityDomainError):
    def __init__(self, value: int) -> None:
        super().__init__(f"TokenLimit must be a positive integer, got {value}")


class InvalidDeploymentTransition(AiSecurityDomainError):
    def __init__(self, from_status: str, to_status: str) -> None:
        super().__init__(f"Invalid AiDeployment status transition {from_status} → {to_status}")
