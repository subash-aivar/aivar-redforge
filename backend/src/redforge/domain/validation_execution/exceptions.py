"""Domain exceptions for the Gated Safe Active Validation bounded context (M11)."""

from redforge.core.exceptions import RedForgeError, ValidationError


class ValidationExecutionError(RedForgeError):
    """Base exception for all ValidationExecution domain errors."""

    def __init__(self, message: str, error_code: str = "VALIDATION_EXECUTION_ERROR") -> None:
        super().__init__(message=message, error_code=error_code)


class ValidationExecutionNotFoundError(ValidationExecutionError):
    def __init__(self, identifier: str) -> None:
        super().__init__(
            message=f"Validation execution '{identifier}' not found",
            error_code="VALIDATION_EXECUTION_NOT_FOUND",
        )


class InvalidExecutionTransitionError(ValidationError):
    """Raised on any illegal ExecutionStatus transition. The lifecycle
    graph is fixed — see value_objects.ExecutionStatus's docstring."""

    def __init__(self, current_status: str, target_status: str) -> None:
        super().__init__(
            message=(
                f"Cannot transition validation execution from '{current_status}' "
                f"to '{target_status}'"
            ),
            details={"current_status": current_status, "target_status": target_status},
        )


class InvalidStepTransitionError(ValidationError):
    def __init__(self, current_status: str, target_status: str) -> None:
        super().__init__(
            message=f"Cannot transition step from '{current_status}' to '{target_status}'",
            details={"current_status": current_status, "target_status": target_status},
        )


class TargetNormalizationError(ValidationError):
    """Raised when a canonical target's endpoint cannot be safely
    normalized for active validation (malformed URL, unsupported
    scheme, userinfo present, ambiguous host syntax)."""

    def __init__(self, reason: str) -> None:
        super().__init__(
            message=f"Target normalization failed: {reason}", details={"reason": reason},
        )


class NetworkBoundaryDeniedError(ValidationError):
    """Raised when a resolved address (initial resolution or a redirect
    hop) is not classified PUBLIC — see value_objects.AddressClass."""

    def __init__(self, address: str, address_class: str) -> None:
        super().__init__(
            message=(
                f"Address '{address}' is classified '{address_class}', "
                "not permitted for active validation"
            ),
            details={"address": address, "address_class": address_class},
        )
