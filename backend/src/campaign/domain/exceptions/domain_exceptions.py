"""Campaign domain exceptions."""

from __future__ import annotations


class CampaignDomainException(Exception):
    """Base exception for campaign domain violations."""


class InvalidStateTransition(CampaignDomainException):
    def __init__(self, from_state: str, to_state: str, aggregate_id: str) -> None:
        super().__init__(
            f"Invalid state transition from '{from_state}' to '{to_state}' "
            f"on aggregate '{aggregate_id}'"
        )
        self.from_state = from_state
        self.to_state = to_state
        self.aggregate_id = aggregate_id


class InvariantViolation(CampaignDomainException):
    def __init__(self, invariant: str, detail: str) -> None:
        super().__init__(f"Invariant violated [{invariant}]: {detail}")
        self.invariant = invariant
        self.detail = detail


class ObjectiveSealedViolation(CampaignDomainException):
    def __init__(self, objective_id: str) -> None:
        super().__init__(f"Objective '{objective_id}' is sealed and cannot be modified")
        self.objective_id = objective_id


class ArchivedImmutabilityViolation(CampaignDomainException):
    def __init__(self, aggregate_id: str) -> None:
        super().__init__(f"Archived aggregate '{aggregate_id}' is immutable and cannot be modified")
        self.aggregate_id = aggregate_id


class TenantMismatch(CampaignDomainException):
    def __init__(self, expected: object, actual: object) -> None:
        super().__init__(f"Tenant mismatch: expected '{expected}', got '{actual}'")
        self.expected = expected
        self.actual = actual


class InvalidArgument(CampaignDomainException):
    def __init__(self, field: str, reason: str) -> None:
        super().__init__(f"Invalid argument '{field}': {reason}")
        self.field = field
        self.reason = reason


class EngagementNotActive(CampaignDomainException):
    def __init__(self, engagement_id: str, state: str) -> None:
        super().__init__(f"Engagement '{engagement_id}' is not active (current state: {state})")
        self.engagement_id = engagement_id
        self.state = state


class TargetResolutionFailed(CampaignDomainException):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Target resolution failed: {reason}")
        self.reason = reason


class DuplicateApproval(CampaignDomainException):
    def __init__(self, approver_id: str, campaign_id: str) -> None:
        super().__init__(f"Approver '{approver_id}' has already approved campaign '{campaign_id}'")
        self.approver_id = approver_id
        self.campaign_id = campaign_id


class OptimisticLockConflict(CampaignDomainException):
    def __init__(self, aggregate_id: str, expected_version: int, actual_version: int) -> None:
        super().__init__(
            f"Optimistic lock conflict on '{aggregate_id}': "
            f"expected version {expected_version}, found {actual_version}"
        )
        self.aggregate_id = aggregate_id
        self.expected_version = expected_version
        self.actual_version = actual_version
