"""Domain exceptions for the Network Security bounded context (M16)."""

from redforge.core.exceptions import RedForgeError, ValidationError


class NetworkSecurityError(RedForgeError):
    """Base exception for all Network Security domain errors."""

    def __init__(self, message: str, error_code: str = "NETWORK_SECURITY_ERROR") -> None:
        super().__init__(message=message, error_code=error_code)


class NetworkValidationRunNotFoundError(NetworkSecurityError):
    def __init__(self, identifier: str) -> None:
        super().__init__(
            message=f"Network validation run '{identifier}' not found",
            error_code="NETWORK_VALIDATION_RUN_NOT_FOUND",
        )


class NetworkMonitoringPolicyNotFoundError(NetworkSecurityError):
    def __init__(self, identifier: str) -> None:
        super().__init__(
            message=f"Network monitoring policy '{identifier}' not found",
            error_code="NETWORK_MONITORING_POLICY_NOT_FOUND",
        )


class InvalidNetworkRunTransitionError(ValidationError):
    """Raised when an illegal NetworkRunStatus transition is attempted."""

    def __init__(self, current_status: str, target_status: str) -> None:
        super().__init__(
            message=f"Cannot transition network validation run from '{current_status}' to "
            f"'{target_status}'",
            details={"current_status": current_status, "target_status": target_status},
        )


class InvalidNetworkPolicyTransitionError(ValidationError):
    def __init__(self, current_status: str, target_status: str) -> None:
        super().__init__(
            message=f"Cannot transition network monitoring policy from '{current_status}' to "
            f"'{target_status}'",
            details={"current_status": current_status, "target_status": target_status},
        )


class NetworkPolicyDisabledForRunError(ValidationError):
    def __init__(self, policy_id: str) -> None:
        super().__init__(
            message=f"Network monitoring policy '{policy_id}' is disabled and cannot be run",
            details={"policy_id": policy_id},
        )


class NetworkAuthorizationDeniedError(ValidationError):
    """Raised when a NetworkValidationRun cannot be authorized — the
    reason_code is always one of NetworkScopeReasonCode, never a free
    string."""

    def __init__(self, reason_code: str, detail: str = "") -> None:
        suffix = f" ({detail})" if detail else ""
        super().__init__(
            message=f"Network validation denied: {reason_code}{suffix}",
            details={"reason_code": reason_code},
        )
