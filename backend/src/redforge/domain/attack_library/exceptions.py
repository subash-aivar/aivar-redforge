"""Domain exceptions for the Attack Library bounded context."""

from redforge.core.exceptions import RedForgeError, ValidationError


class AttackLibraryError(RedForgeError):
    """Base exception for all Attack Library domain errors."""

    def __init__(self, message: str) -> None:
        super().__init__(message=message, error_code="ATTACK_LIBRARY_ERROR")


class AttackNotFoundError(AttackLibraryError):
    """Raised when an attack definition cannot be located."""

    def __init__(self, identifier: str) -> None:
        super().__init__(message=f"Attack '{identifier}' not found")
        self.error_code = "ATTACK_NOT_FOUND"


class InvalidAttackTransitionError(ValidationError):
    """Raised when an invalid attack status transition is attempted."""

    def __init__(self, current_status: str, target_status: str) -> None:
        super().__init__(
            message=(
                f"Cannot transition attack from '{current_status}' "
                f"to '{target_status}'"
            ),
            details={"current_status": current_status, "target_status": target_status},
        )


class AttackImmutableError(ValidationError):
    """Raised when modifying an archived or superseded attack."""

    def __init__(self, attack_id: str) -> None:
        super().__init__(
            message=f"Attack '{attack_id}' is immutable (archived/superseded)",
            details={"attack_id": attack_id},
        )
