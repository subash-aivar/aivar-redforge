"""Domain exceptions for the Finding bounded context."""

from redforge.core.exceptions import RedForgeError, ValidationError


class FindingError(RedForgeError):
    """Base exception for all Finding domain errors."""

    def __init__(self, message: str) -> None:
        super().__init__(message=message, error_code="FINDING_ERROR")


class FindingNotFoundError(FindingError):
    """Raised when a Finding cannot be located."""

    def __init__(self, identifier: str) -> None:
        super().__init__(message=f"Finding '{identifier}' not found")
        self.error_code = "FINDING_NOT_FOUND"


class InvalidFindingTransitionError(ValidationError):
    """Raised when an invalid finding status transition is attempted."""

    def __init__(self, current_status: str, target_status: str) -> None:
        super().__init__(
            message=(
                f"Cannot transition finding from '{current_status}' "
                f"to '{target_status}'"
            ),
            details={"current_status": current_status, "target_status": target_status},
        )


class FindingClosedError(ValidationError):
    """Raised when attempting to modify a closed finding."""

    def __init__(self, finding_id: str) -> None:
        super().__init__(
            message=f"Finding '{finding_id}' is closed and cannot be modified",
            details={"finding_id": finding_id},
        )
