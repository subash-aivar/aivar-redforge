"""Domain exceptions for the Execution Engine bounded context."""

from redforge.core.exceptions import RedForgeError, ValidationError


class ExecutionError(RedForgeError):
    """Base exception for all Execution Engine domain errors."""

    def __init__(self, message: str) -> None:
        super().__init__(message=message, error_code="EXECUTION_ERROR")


class PlanNotFoundError(ExecutionError):
    """Raised when an Execution Plan cannot be located."""

    def __init__(self, identifier: str) -> None:
        super().__init__(message=f"Execution plan '{identifier}' not found")
        self.error_code = "PLAN_NOT_FOUND"


class InvalidPlanTransitionError(ValidationError):
    """Raised when an invalid plan status transition is attempted."""

    def __init__(self, current_status: str, target_status: str) -> None:
        super().__init__(
            message=(
                f"Cannot transition execution plan from '{current_status}' "
                f"to '{target_status}'"
            ),
            details={"current_status": current_status, "target_status": target_status},
        )


class PlanAlreadyTerminalError(ValidationError):
    """Raised when modifying a terminal-state plan."""

    def __init__(self, plan_id: str) -> None:
        super().__init__(
            message=f"Execution plan '{plan_id}' is in a terminal state",
            details={"plan_id": plan_id},
        )


class PlanEmptyError(ValidationError):
    """Raised when starting a plan with no stages."""

    def __init__(self, plan_id: str) -> None:
        super().__init__(
            message=f"Execution plan '{plan_id}' has no stages to execute",
            details={"plan_id": plan_id},
        )
