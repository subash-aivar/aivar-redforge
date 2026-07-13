"""Domain exceptions for the Validation Policy bounded context."""

from redforge.core.exceptions import RedForgeError, ValidationError


class PolicyError(RedForgeError):
    """Base exception for all Validation Policy domain errors."""

    def __init__(self, message: str) -> None:
        super().__init__(message=message, error_code="POLICY_ERROR")


class PolicyNotFoundError(PolicyError):
    """Raised when a Validation Policy cannot be located."""

    def __init__(self, identifier: str) -> None:
        super().__init__(message=f"Validation Policy '{identifier}' not found")
        self.error_code = "POLICY_NOT_FOUND"


class InvalidPolicyTransitionError(ValidationError):
    """Raised when an invalid policy status transition is attempted."""

    def __init__(self, current_status: str, target_status: str) -> None:
        super().__init__(
            message=(
                f"Cannot transition policy from '{current_status}' "
                f"to '{target_status}'"
            ),
            details={"current_status": current_status, "target_status": target_status},
        )


class PolicyImmutableError(ValidationError):
    """Raised when modifying an archived or superseded policy."""

    def __init__(self, policy_id: str) -> None:
        super().__init__(
            message=f"Policy '{policy_id}' is immutable",
            details={"policy_id": policy_id},
        )


class PolicyEmptyError(ValidationError):
    """Raised when publishing a policy with no attacks attached."""

    def __init__(self, policy_id: str) -> None:
        super().__init__(
            message=f"Policy '{policy_id}' must have at least one attack to publish",
            details={"policy_id": policy_id},
        )
