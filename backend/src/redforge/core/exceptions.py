"""Domain exception hierarchy for AIVAR RedForge.

All domain exceptions inherit from RedForgeError. These exceptions carry
semantic meaning independent of any transport protocol. The infrastructure
layer is responsible for mapping these to HTTP responses, gRPC status codes,
or any other transport representation.
"""


class RedForgeError(Exception):
    """Base exception for all AIVAR RedForge domain errors.

    Attributes:
        message: Human-readable error description.
        error_code: Machine-readable error identifier for client consumption.
    """

    def __init__(self, message: str, error_code: str = "REDFORGE_ERROR") -> None:
        self.message = message
        self.error_code = error_code
        super().__init__(message)


class NotFoundError(RedForgeError):
    """Raised when a requested resource does not exist."""

    def __init__(self, resource: str, identifier: str) -> None:
        super().__init__(
            message=f"{resource} with identifier '{identifier}' not found",
            error_code="NOT_FOUND",
        )
        self.resource = resource
        self.identifier = identifier


class ValidationError(RedForgeError):
    """Raised when input data fails domain validation rules."""

    def __init__(self, message: str, details: dict[str, str] | None = None) -> None:
        super().__init__(message=message, error_code="VALIDATION_ERROR")
        self.details: dict[str, str] = details or {}


class AuthenticationError(RedForgeError):
    """Raised when a request cannot be authenticated.

    Covers: missing bearer token, malformed token, invalid/expired
    signature, or a token whose subject no longer resolves to an active
    user. This is the single canonical authentication-failure exception
    for the transport boundary — application-layer login/credential
    failures (bad password, unknown email) also raise this so every
    "you are not who you say you are" case maps to the same 401 contract.
    """

    def __init__(self, message: str = "Authentication required") -> None:
        super().__init__(message=message, error_code="AUTHENTICATION_ERROR")


class AuthorizationError(RedForgeError):
    """Raised when an authenticated actor is not permitted to perform an
    operation — insufficient role/permission, or no membership in the
    requested organization at all. Distinct from AuthenticationError:
    this means "we know who you are, and the answer is still no."
    """

    def __init__(self, message: str = "Operation not permitted") -> None:
        super().__init__(message=message, error_code="AUTHORIZATION_ERROR")


class ConflictError(RedForgeError):
    """Raised when an operation conflicts with the current state of a resource."""

    def __init__(self, message: str) -> None:
        super().__init__(message=message, error_code="CONFLICT")


class CredentialResolutionError(RedForgeError):
    """Raised when a provider auth_ref cannot be resolved to a credential.

    This is a configuration error — the server-side secret reference is
    missing or unset. The resolved credential value is NEVER included in
    this exception or its string representation.
    """

    def __init__(self, auth_ref: str) -> None:
        super().__init__(
            message=f"Credential reference '{auth_ref}' is not configured on this server. "
                    "Register the provider with a valid server-side credential reference.",
            error_code="CREDENTIAL_NOT_CONFIGURED",
        )
        self.auth_ref = auth_ref
