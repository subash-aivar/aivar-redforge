"""CSPM domain exceptions."""

from __future__ import annotations

from redforge.core.exceptions import ConflictError, NotFoundError, ValidationError


class InvalidCSPMArgumentError(ValidationError):
    def __init__(self, field: str, message: str) -> None:
        self.field = field
        super().__init__(message=f"{field}: {message}", details={field: message})


class CSPMFindingNotFoundError(NotFoundError):
    def __init__(self, finding_id: str) -> None:
        super().__init__(resource="CSPMFinding", identifier=finding_id)
        self.finding_id = finding_id


class CSPMPolicyNotFoundError(NotFoundError):
    def __init__(self, policy_id: str) -> None:
        super().__init__(resource="CSPMPolicy", identifier=policy_id)
        self.policy_id = policy_id


class CSPMEvaluationNotFoundError(NotFoundError):
    def __init__(self, evaluation_id: str) -> None:
        super().__init__(resource="CSPMEvaluation", identifier=evaluation_id)
        self.evaluation_id = evaluation_id


class InvalidFindingTransitionError(ConflictError):
    def __init__(self, finding_id: str, from_status: str, to_status: str) -> None:
        self.finding_id = finding_id
        super().__init__(
            message=(
                f"Invalid CSPMFinding transition {from_status} -> {to_status} "
                f"for finding={finding_id}"
            ),
        )


class PolicyEvaluationError(ValidationError):
    def __init__(self, policy_id: str, message: str) -> None:
        self.policy_id = policy_id
        super().__init__(message=f"policy={policy_id}: {message}", details={"policy_id": policy_id})
