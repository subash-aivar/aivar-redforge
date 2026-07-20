"""Cloud risk domain exceptions."""

from __future__ import annotations

from redforge.core.exceptions import ConflictError, NotFoundError, ValidationError


class InvalidRiskArgumentError(ValidationError):
    def __init__(self, field: str, message: str) -> None:
        self.field = field
        super().__init__(message=f"{field}: {message}", details={field: message})


class CloudRiskNotFoundError(NotFoundError):
    def __init__(self, risk_id: str) -> None:
        super().__init__(resource="CloudRiskScore", identifier=risk_id)
        self.risk_id = risk_id


class InvalidRiskTransitionError(ConflictError):
    def __init__(self, risk_id: str, from_state: str, to_state: str) -> None:
        super().__init__(
            message=f"Invalid risk transition {from_state} -> {to_state} for risk={risk_id}",
        )
