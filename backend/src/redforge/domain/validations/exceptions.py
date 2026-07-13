"""Domain exceptions for the Validation bounded context."""

from redforge.core.exceptions import RedForgeError, ValidationError


class ValidationRunError(RedForgeError):
    """Base exception for all Validation Run domain errors."""

    def __init__(self, message: str) -> None:
        super().__init__(message=message, error_code="VALIDATION_RUN_ERROR")


class ValidationRunNotFoundError(ValidationRunError):
    """Raised when a Validation Run cannot be located."""

    def __init__(self, identifier: str) -> None:
        super().__init__(message=f"Validation run '{identifier}' not found")
        self.error_code = "VALIDATION_RUN_NOT_FOUND"


class InvalidValidationTransitionError(ValidationError):
    """Raised when an invalid status transition is attempted."""

    def __init__(self, current_status: str, target_status: str) -> None:
        super().__init__(
            message=(
                f"Cannot transition validation run from '{current_status}' "
                f"to '{target_status}'"
            ),
            details={"current_status": current_status, "target_status": target_status},
        )


class ValidationAlreadyCompleteError(ValidationError):
    """Raised when modifying a terminal-state validation run."""

    def __init__(self, run_id: str) -> None:
        super().__init__(
            message=f"Validation run '{run_id}' is already in a terminal state",
            details={"run_id": run_id},
        )
