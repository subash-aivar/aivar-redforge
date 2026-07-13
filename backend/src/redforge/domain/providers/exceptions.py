"""Domain exceptions for the Provider Adapter Framework."""

from redforge.core.exceptions import RedForgeError, ValidationError


class ProviderFrameworkError(RedForgeError):
    """Base exception for all Provider Framework errors."""

    def __init__(self, message: str) -> None:
        super().__init__(message=message, error_code="PROVIDER_ERROR")


class ProviderNotFoundError(ProviderFrameworkError):
    """Raised when a registered provider cannot be located."""

    def __init__(self, identifier: str) -> None:
        super().__init__(message=f"Provider '{identifier}' not found")
        self.error_code = "PROVIDER_NOT_FOUND"


class ProviderUnavailableError(ProviderFrameworkError):
    """Raised when a provider is not available for requests."""

    def __init__(self, provider_name: str) -> None:
        super().__init__(message=f"Provider '{provider_name}' is unavailable")
        self.error_code = "PROVIDER_UNAVAILABLE"


class CapabilityNotSupportedError(ValidationError):
    """Raised when a requested capability is not supported by the provider."""

    def __init__(self, provider_name: str, capability: str) -> None:
        super().__init__(
            message=(
                f"Provider '{provider_name}' does not support "
                f"capability '{capability}'"
            ),
            details={"provider": provider_name, "capability": capability},
        )


class ProviderRateLimitError(ProviderFrameworkError):
    """Raised when a provider rate limit is exceeded."""

    def __init__(self, provider_name: str) -> None:
        super().__init__(
            message=f"Provider '{provider_name}' rate limit exceeded"
        )
        self.error_code = "PROVIDER_RATE_LIMIT"
