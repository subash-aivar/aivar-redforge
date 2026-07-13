"""Domain exceptions for the AI Target bounded context."""

from redforge.core.exceptions import RedForgeError, ValidationError


class TargetError(RedForgeError):
    """Base exception for all AI Target domain errors."""

    def __init__(self, message: str) -> None:
        super().__init__(message=message, error_code="TARGET_ERROR")


class TargetNotFoundError(TargetError):
    """Raised when an AI Target cannot be located."""

    def __init__(self, identifier: str) -> None:
        super().__init__(message=f"AI Target '{identifier}' not found")
        self.error_code = "TARGET_NOT_FOUND"


class TargetInactiveError(ValidationError):
    """Raised when an operation requires an active target."""

    def __init__(self, target_id: str) -> None:
        super().__init__(
            message=f"AI Target '{target_id}' is not active",
            details={"target_id": target_id},
        )


class TargetArchivedError(ValidationError):
    """Raised when an operation is attempted on an archived target."""

    def __init__(self, target_id: str) -> None:
        super().__init__(
            message=f"AI Target '{target_id}' is archived and cannot be modified",
            details={"target_id": target_id},
        )


class InvalidTargetTransitionError(ValidationError):
    """Raised when an invalid status transition is attempted."""

    def __init__(self, current_status: str, target_status: str) -> None:
        super().__init__(
            message=(
                f"Cannot transition AI Target from '{current_status}' "
                f"to '{target_status}'"
            ),
            details={"current_status": current_status, "target_status": target_status},
        )


class DuplicateTagError(ValidationError):
    """Raised when attempting to add a tag that already exists on the target."""

    def __init__(self, tag: str) -> None:
        super().__init__(
            message=f"Tag '{tag}' already exists on this target",
            details={"tag": tag},
        )


class PolicyAlreadyAttachedError(ValidationError):
    """Raised when attempting to attach a policy that is already attached."""

    def __init__(self, policy_id: str) -> None:
        super().__init__(
            message=f"Validation policy '{policy_id}' is already attached",
            details={"policy_id": policy_id},
        )


class PolicyNotAttachedError(ValidationError):
    """Raised when attempting to detach a policy that is not attached."""

    def __init__(self, policy_id: str) -> None:
        super().__init__(
            message=f"Validation policy '{policy_id}' is not attached to this target",
            details={"policy_id": policy_id},
        )
