"""Domain exceptions for the Continuous Validation bounded context (M14)."""

from redforge.core.exceptions import RedForgeError, ValidationError


class ContinuousValidationError(RedForgeError):
    """Base exception for all Continuous Validation domain errors."""

    def __init__(self, message: str, error_code: str = "CONTINUOUS_VALIDATION_ERROR") -> None:
        super().__init__(message=message, error_code=error_code)


class ContinuousValidationPolicyNotFoundError(ContinuousValidationError):
    """Raised when a ContinuousValidationPolicy cannot be located."""

    def __init__(self, identifier: str) -> None:
        super().__init__(
            message=f"Continuous validation policy '{identifier}' not found",
            error_code="CONTINUOUS_VALIDATION_POLICY_NOT_FOUND",
        )


class InvalidPolicyTransitionError(ValidationError):
    """Raised when an illegal PolicyLifecycle transition is attempted.
    The lifecycle graph is fixed — see PolicyLifecycle's docstring —
    there is no code path that can mutate lifecycle outside
    ContinuousValidationPolicy's own methods."""

    def __init__(self, current_status: str, target_status: str) -> None:
        super().__init__(
            message=(
                f"Cannot transition continuous validation policy from "
                f"'{current_status}' to '{target_status}'"
            ),
            details={"current_status": current_status, "target_status": target_status},
        )


class PolicyDisabledForExecutionError(ValidationError):
    """Raised when 'Run Now' (or any other execution trigger) is
    attempted against a DISABLED policy. DISABLED is terminal — see
    PolicyLifecycle's own docstring — and that must hold for every
    execution path, not merely for lifecycle transition attempts. A
    disabled policy grants no continuing eligibility to run at all."""

    def __init__(self, policy_id: str) -> None:
        super().__init__(
            message=f"Continuous validation policy '{policy_id}' is disabled and cannot be run",
            details={"policy_id": policy_id},
        )


class PolicyNotDueError(ValidationError):
    """Raised when a run-now/claim is attempted against a policy that is
    not eligible: not ACTIVE, or not yet at its next_due_at boundary
    (for the scheduler's own claim path — never raised for the
    operator-facing 'Run Now' path, which uses ON_DEMAND and bypasses
    the due-boundary check entirely by design)."""

    def __init__(self, policy_id: str, reason: str) -> None:
        super().__init__(
            message=f"Continuous validation policy '{policy_id}' is not due: {reason}",
            details={"policy_id": policy_id, "reason": reason},
        )
